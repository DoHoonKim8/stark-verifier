use std::sync::{Arc, Mutex};
use std::time::Instant;

use colored::Colorize;
use itertools::Itertools;
use plonky2::fri::reduction_strategies::FriReductionStrategy;
use plonky2::fri::FriConfig;
use plonky2::hash::hash_types::HashOut;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, VerifierCircuitData, VerifierCircuitTarget};
use plonky2::plonk::config::PoseidonGoldilocksConfig;
use plonky2::plonk::proof::ProofWithPublicInputs;
use rayon::prelude::ParallelIterator;
use rayon::slice::ParallelSlice;

use crate::plonky2_semaphore::report_elapsed;

use super::access_set::AccessSet;
use super::signal::{Signal, C, F};

type InnerC = PoseidonGoldilocksConfig;

impl AccessSet {
    fn aggregate_signals(
        &self,
        signal0: Signal,
        signal1: Signal,
        verifier_data: &VerifierCircuitData<F, C, 2>,
        _is_final: bool,
    ) -> (Signal, VerifierCircuitData<F, C, 2>) {
        let config = CircuitConfig {
            zero_knowledge: true,
            num_wires: 135,
            num_routed_wires: 80,
            num_constants: 2,
            use_base_arithmetic_gate: true,
            security_bits: 100,
            num_challenges: 2,
            max_quotient_degree_factor: 8,
            fri_config: FriConfig {
                rate_bits: 3,
                cap_height: 4,
                proof_of_work_bits: 16,
                reduction_strategy: FriReductionStrategy::ConstantArityBits(1, 5), // 3, 5
                num_query_rounds: 28,                                              // 28
            },
        };
        let mut builder = CircuitBuilder::new(config);
        let mut pw = PartialWitness::new();

        let public_inputs0: Vec<F> = self
            .0
            .cap
            .0
            .iter()
            .flat_map(|h| h.elements)
            .chain(signal0.nullifier.clone().into_iter().flatten().to_owned())
            .chain(signal0.topics.clone().into_iter().flatten().to_owned())
            .collect();
        let public_inputs1: Vec<F> = self
            .0
            .cap
            .0
            .iter()
            .flat_map(|h| h.elements)
            .chain(signal1.nullifier.clone().into_iter().flatten().to_owned())
            .chain(signal1.topics.clone().into_iter().flatten().to_owned())
            .collect();

        let proof_target0 = builder.add_virtual_proof_with_pis::<InnerC>(&verifier_data.common);
        pw.set_proof_with_pis_target(
            &proof_target0,
            &ProofWithPublicInputs {
                proof: signal0.proof,
                public_inputs: public_inputs0.clone(),
            },
        );
        let proof_target1 = builder.add_virtual_proof_with_pis::<InnerC>(&verifier_data.common);
        pw.set_proof_with_pis_target(
            &proof_target1,
            &ProofWithPublicInputs {
                proof: signal1.proof,
                public_inputs: public_inputs1.clone(),
            },
        );

        let vd_target = VerifierCircuitTarget {
            constants_sigmas_cap: builder
                .add_virtual_cap(verifier_data.common.config.fri_config.cap_height),
            circuit_digest: builder.add_virtual_hash(),
        };
        pw.set_cap_target(
            &vd_target.constants_sigmas_cap,
            &verifier_data.verifier_only.constants_sigmas_cap,
        );
        pw.set_hash_target(
            vd_target.circuit_digest,
            verifier_data.verifier_only.circuit_digest,
        );

        builder.verify_proof::<InnerC>(&proof_target0, &vd_target, &verifier_data.common);
        builder.verify_proof::<InnerC>(&proof_target1, &vd_target, &verifier_data.common);

        // register public inputs : cap + nullifiers(0+1) + topics(0+1)
        let merkle_root = builder.add_virtual_hash();
        builder.register_public_inputs(&merkle_root.elements);
        pw.set_hash_target(merkle_root, self.0.cap.0[0]);

        let nullifiers =
            builder.add_virtual_hashes(signal0.nullifier.len() + signal1.nullifier.len());
        builder.register_public_inputs(&nullifiers.iter().flat_map(|n| n.elements).collect_vec());
        for i in 0..signal0.nullifier.len() {
            for j in 0..4 {
                builder.connect(
                    proof_target0.public_inputs[4 * (i + 1) + j],
                    nullifiers[i].elements[j],
                );
            }
        }
        for i in 0..signal1.nullifier.len() {
            for j in 0..4 {
                builder.connect(
                    proof_target1.public_inputs[4 * (i + 1) + j],
                    nullifiers[signal0.nullifier.len() + i].elements[j],
                );
            }
        }
        for (target, value) in nullifiers.iter().zip(
            signal0
                .nullifier
                .clone()
                .into_iter()
                .chain(signal1.nullifier.clone()),
        ) {
            pw.set_hash_target(*target, HashOut::from(value));
        }

        let topics = builder.add_virtual_hashes(signal0.topics.len() + signal1.topics.len());
        builder.register_public_inputs(&topics.iter().flat_map(|n| n.elements).collect_vec());
        for i in 0..signal0.topics.len() {
            for j in 0..4 {
                builder.connect(
                    proof_target0.public_inputs[4 * (1 + signal0.nullifier.len() + i) + j],
                    topics[i].elements[j],
                );
            }
        }
        for i in 0..signal1.topics.len() {
            for j in 0..4 {
                builder.connect(
                    proof_target1.public_inputs[4 * (1 + signal1.nullifier.len() + i) + j],
                    topics[signal0.topics.len() + i].elements[j],
                );
            }
        }
        for (target, value) in topics.iter().zip(
            signal0
                .topics
                .clone()
                .into_iter()
                .chain(signal1.topics.clone()),
        ) {
            pw.set_hash_target(*target, HashOut::from(value));
        }

        let data = builder.build();
        let recursive_proof = data.prove(pw).unwrap();

        // data.verify(recursive_proof.clone()).unwrap();
        let next_signal = Signal {
            topics: signal0
                .topics
                .into_iter()
                .chain(signal1.topics.into_iter())
                .collect_vec(),
            nullifier: signal0
                .nullifier
                .into_iter()
                .chain(signal1.nullifier.into_iter())
                .collect_vec(),
            proof: recursive_proof.proof,
        };
        (next_signal, data.verifier_data())
    }

    pub fn aggregate(
        &self,
        aggregation_targets: Arc<Mutex<Vec<Signal>>>,
        mut verifier_circuit_data: Arc<Mutex<Option<VerifierCircuitData<F, C, 2>>>>,
    ) -> (Signal, VerifierCircuitData<F, C, 2>) {
        let aggregation_targets_len = aggregation_targets.lock().unwrap().len();
        println!(
            "{}",
            format!("Start aggregating {aggregation_targets_len} proofs")
                .white()
                .bold()
        );
        let now = Instant::now();
        while aggregation_targets.lock().unwrap().len() != 1 {
            let next_aggregation_targets = Arc::new(Mutex::new(vec![]));
            let next_verifier_circuit_data = Arc::new(Mutex::new(None));
            // lock `verifier_circuit_data`
            let verifier_circuit_data_read = verifier_circuit_data
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .clone();
            let is_final = aggregation_targets.lock().unwrap().len() == 2;
            aggregation_targets
                .lock()
                .unwrap()
                .par_chunks_exact(2)
                .for_each(|signals| {
                    let (next_signal, next_vd) = self.aggregate_signals(
                        signals[0].clone(),
                        signals[1].clone(),
                        &verifier_circuit_data_read,
                        is_final,
                    );
                    next_aggregation_targets.lock().unwrap().push(next_signal);
                    let mut next_verifier_circuit_data = next_verifier_circuit_data.lock().unwrap();
                    if next_verifier_circuit_data.is_none() {
                        next_verifier_circuit_data.replace(next_vd);
                    }
                });
            // drop the lock for `verifier_circuit_data`
            drop(verifier_circuit_data_read);
            aggregation_targets.lock().unwrap().clear();
            aggregation_targets
                .lock()
                .unwrap()
                .extend_from_slice(&next_aggregation_targets.lock().unwrap());
            verifier_circuit_data = next_verifier_circuit_data.clone();
        }
        report_elapsed(now);
        (
            aggregation_targets.lock().unwrap()[0].clone(),
            verifier_circuit_data
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .clone(),
        )
    }

    pub fn finalize(&self, _final_signal: &Signal) {
        // Prove that the aggregation proof is valid inside SNARK
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{Arc, Mutex},
        time::Instant,
    };

    use anyhow::Result;
    use colored::Colorize;
    use num_traits::pow;
    use plonky2::{
        field::types::{Field, Sample},
        hash::{merkle_tree::MerkleTree, poseidon::PoseidonHash},
        plonk::{config::Hasher, proof::ProofWithPublicInputs},
    };
    use rayon::prelude::{IntoParallelIterator, ParallelIterator};

    use crate::{
        plonky2_semaphore::{
            access_set::AccessSet,
            recursion::report_elapsed,
            signal::{Digest, F},
        },
        snark::verifier_api::verify_inside_snark,
    };

    fn semaphore_aggregation(
        num_proofs: usize,
        access_set: &AccessSet,
        private_keys: &Vec<Digest>,
    ) -> Result<()> {
        // Generate 64 Semaphore proofs
        let aggregation_targets = Arc::new(Mutex::new(vec![]));
        let verifier_circuit_data = Arc::new(Mutex::new(None));
        let now = Instant::now();
        println!(
            "{}",
            format!("Generating {num_proofs} Semaphore proofs")
                .white()
                .bold()
        );
        (0..num_proofs).into_par_iter().for_each(|i| {
            let topic = F::rand_array();
            let (signal, vd) = access_set.make_signal(private_keys[i], topic, i).unwrap();
            aggregation_targets.lock().unwrap().push(signal);
            let mut verifier_circuit_data = verifier_circuit_data.lock().unwrap();
            if verifier_circuit_data.is_none() {
                verifier_circuit_data.replace(vd);
            }
        });
        report_elapsed(now);
        let (final_signal, verifier_circuit_data) =
            access_set.aggregate(aggregation_targets.clone(), verifier_circuit_data.clone());
        let proof = ProofWithPublicInputs {
            proof: final_signal.proof,
            public_inputs: access_set
                .0
                .cap
                .0
                .iter()
                .flat_map(|h| h.elements)
                .chain(
                    final_signal
                        .nullifier
                        .clone()
                        .into_iter()
                        .flatten()
                        .to_owned(),
                )
                .chain(final_signal.topics.clone().into_iter().flatten().to_owned())
                .collect(),
        };
        verify_inside_snark((
            proof,
            verifier_circuit_data.verifier_only.clone(),
            verifier_circuit_data.common.clone(),
        ));

        Ok(())
    }

    #[test]
    fn test_semaphore_aggregation() -> Result<()> {
        let n = 1 << 20;
        let private_keys: Vec<Digest> = (0..n).map(|_| F::rand_array()).collect();
        let public_keys: Vec<Vec<F>> = private_keys
            .iter()
            .map(|&sk| {
                PoseidonHash::hash_no_pad(&[sk, [F::ZERO; 4]].concat())
                    .elements
                    .to_vec()
            })
            .collect();
        let access_set = AccessSet(MerkleTree::new(public_keys, 0));
        for i in 1..8 {
            semaphore_aggregation(pow(2, i), &access_set, &private_keys)?;
        }
        Ok(())
    }
}
