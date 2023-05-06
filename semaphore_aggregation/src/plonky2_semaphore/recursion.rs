use itertools::Itertools;
use num_traits::pow;
use plonky2::fri::reduction_strategies::FriReductionStrategy;
use plonky2::fri::FriConfig;
use plonky2::hash::hash_types::HashOut;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, VerifierCircuitData, VerifierCircuitTarget};
use plonky2::plonk::config::PoseidonGoldilocksConfig;
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2::util::log2_strict;

use super::access_set::AccessSet;
use super::signal::{Digest, Signal, C, F};

type InnerC = PoseidonGoldilocksConfig;

impl AccessSet {
    pub fn aggregate_signals(
        &self,
        signal0: Signal,
        signal1: Signal,
        verifier_data: &VerifierCircuitData<F, C, 2>,
        level: usize, // remove this later
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

        let public_inputs0: Vec<F> = if level == 0 {
            self.0
                .cap
                .0
                .iter()
                .flat_map(|h| h.elements)
                .chain(signal0.nullifier.clone().into_iter().flatten().to_owned())
                .chain(signal0.topics.clone().into_iter().flatten().to_owned())
                .collect()
        } else {
            vec![]
        };
        let public_inputs1: Vec<F> = if level == 0 {
            self.0
                .cap
                .0
                .iter()
                .flat_map(|h| h.elements)
                .chain(signal1.nullifier.clone().into_iter().flatten().to_owned())
                .chain(signal1.topics.clone().into_iter().flatten().to_owned())
                .collect()
        } else {
            vec![]
        };

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

        // let merkle_root = builder.add_virtual_hash();
        // builder.register_public_inputs(&merkle_root.elements);
        // pw.set_hash_target(merkle_root, self.0.cap.0[0]);

        // let nullifier =
        //     builder.add_virtual_hashes(signal0.nullifier.len() + signal1.nullifier.len());
        // builder.register_public_inputs(&nullifier.iter().flat_map(|n| n.elements).collect_vec());
        // for i in 0..signal0.nullifier.len() {
        //     for j in 0..4 {
        //         builder.connect(
        //             proof_target0.public_inputs[4 * (i + 1) + j],
        //             nullifier[i].elements[j],
        //         );
        //     }
        // }
        // for i in 0..signal1.nullifier.len() {
        //     for j in 0..4 {
        //         builder.connect(
        //             proof_target1.public_inputs[4 * (i + 1) + j],
        //             nullifier[signal0.nullifier.len() + i].elements[j],
        //         );
        //     }
        // }
        // for (target, value) in nullifier.iter().zip(
        //     signal0
        //         .nullifier
        //         .clone()
        //         .into_iter()
        //         .chain(signal1.nullifier.clone()),
        // ) {
        //     pw.set_hash_target(*target, HashOut::from(value));
        // }

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

    pub fn finalize(&self, final_signal: &Signal) {
        // Prove that the aggregation proof is valid inside SNARK
        todo!()
    }
}

mod tests {
    use std::{time::Instant, sync::{Mutex, Arc}};

    use anyhow::Result;
    use colored::Colorize;
    use plonky2::{
        field::types::{Field, Sample},
        hash::{merkle_tree::MerkleTree, poseidon::PoseidonHash},
        plonk::{config::Hasher, proof::ProofWithPublicInputs},
    };
    use rayon::{slice::ParallelSlice, prelude::{IntoParallelIterator, ParallelIterator}};

    use crate::{
        plonky2_semaphore::{
            access_set::AccessSet,
            signal::{Digest, F},
        },
        snark::verifier_api::{verify_inside_snark, verify_inside_snark_mock},
    };

    fn report_elapsed(now: Instant) {
        println!(
            "{}",
            format!("Took {} seconds", now.elapsed().as_secs())
                .blue()
                .bold()
        );
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

        // // signal0, signal1
        // let i = 12;
        // let topic0 = F::rand_array();
        // let (signal0, _) = access_set.make_signal(private_keys[i], topic0, i)?;

        // let i = 24;
        // let topic1 = F::rand_array();
        // let (signal1, vd) = access_set.make_signal(private_keys[i], topic1, i)?;

        // let (signal, aggregation_circuit_vd) = access_set.aggregate_signals(signal0, signal1, &vd);
        // let proof = ProofWithPublicInputs {
        //     proof: signal.proof,
        //     public_inputs: vec![],
        // };

        // verify_inside_snark((
        //     proof,
        //     aggregation_circuit_vd.verifier_only.clone(),
        //     aggregation_circuit_vd.common.clone(),
        // ));

        // Generate 64 Semaphore proofs
        let aggregation_targets = Arc::new(Mutex::new(vec![]));
        let mut verifier_circuit_data = Arc::new(Mutex::new(None));
        let num_proofs = 32;
        let now = Instant::now();
        println!(
            "{}",
            format!("Generating {num_proofs} Semaphore proofs").white().bold()
        );
        (0..num_proofs).into_par_iter().for_each(|i| { 
            let topic = F::rand_array();
            let (signal, vd) = access_set.make_signal(private_keys[i], topic, i).unwrap();
            aggregation_targets.lock().unwrap().push(signal);
            if verifier_circuit_data.lock().unwrap().is_none() {
                verifier_circuit_data.lock().unwrap().replace(vd);
            }
        });
        report_elapsed(now);
        let aggregation_targets_len = aggregation_targets.lock().unwrap().len();
        assert_eq!(num_proofs, aggregation_targets_len);
        println!(
            "{}",
            format!("Start aggregating {aggregation_targets_len} proofs")
                .white()
                .bold()
        );
        let mut level = 0;
        let now = Instant::now();
        while aggregation_targets.lock().unwrap().len() != 1 {
            let next_aggregation_targets = Arc::new(Mutex::new(vec![]));
            let next_verifier_circuit_data = Arc::new(Mutex::new(None));
            aggregation_targets.lock().unwrap().par_chunks_exact(2).for_each(|signals| {
                let (next_signal, next_vd) = access_set.aggregate_signals(
                    signals[0].clone(),
                    signals[1].clone(),
                    verifier_circuit_data.lock().unwrap().as_ref().unwrap(),
                    level,
                );
                next_aggregation_targets.lock().unwrap().push(next_signal);
                next_verifier_circuit_data.lock().unwrap().replace(next_vd);
            });
            aggregation_targets.lock().unwrap().clear();
            aggregation_targets.lock().unwrap().extend_from_slice(&next_aggregation_targets.lock().unwrap());
            verifier_circuit_data = next_verifier_circuit_data.clone();
            level += 1;
        }
        report_elapsed(now);
        let final_signal = aggregation_targets.lock().unwrap()[0].clone();
        let proof = ProofWithPublicInputs {
            proof: final_signal.proof,
            public_inputs: vec![], // this should be fixed
        };

        let verifier_circuit_data = verifier_circuit_data.lock().unwrap().as_ref().unwrap().clone();
        verify_inside_snark((
            proof,
            verifier_circuit_data
                .verifier_only
                .clone(),
            verifier_circuit_data.common.clone(),
        ));

        Ok(())
    }
}
