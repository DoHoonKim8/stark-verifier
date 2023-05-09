use std::time::Instant;

use anyhow::Result;
use colored::Colorize;
use plonky2::fri::reduction_strategies::FriReductionStrategy;
use plonky2::fri::FriConfig;
use plonky2::hash::merkle_tree::MerkleTree;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::iop::witness::PartialWitness;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, VerifierCircuitData};
use plonky2::plonk::config::Hasher;
use plonky2::plonk::proof::ProofWithPublicInputs;

use crate::snark::verifier_api::verify_inside_snark;

use super::report_elapsed;
use super::signal::{Digest, Signal, C, F};

pub struct AccessSet(pub MerkleTree<F, PoseidonHash>);

impl AccessSet {
    pub fn verify_signal(
        &self,
        signal: Signal,
        verifier_data: &VerifierCircuitData<F, C, 2>,
    ) -> Result<()> {
        let public_inputs: Vec<F> = self
            .0
            .cap
            .0
            .iter()
            .flat_map(|h| h.elements)
            .chain(signal.nullifier.into_iter().flatten().to_owned())
            .chain(signal.topics.into_iter().flatten().to_owned())
            .collect();

        // verifier_data.verify(ProofWithPublicInputs {
        //     proof: signal.proof,
        //     public_inputs,
        // })
        let proof = (
            ProofWithPublicInputs {
                proof: signal.proof,
                public_inputs,
            },
            verifier_data.verifier_only.clone(),
            verifier_data.common.clone(),
        );
        verify_inside_snark(proof);
        Ok(())
    }

    pub fn make_signal(
        &self,
        private_key: Digest,
        topic: Digest,
        public_key_index: usize,
    ) -> Result<(Signal, VerifierCircuitData<F, C, 2>)> {
        let nullifier = PoseidonHash::hash_no_pad(&[private_key, topic].concat()).elements;
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

        let targets = self.semaphore_circuit(&mut builder);
        self.fill_semaphore_targets(&mut pw, private_key, topic, public_key_index, targets);

        let data = builder.build();
        println!(
            "{}",
            format!("Generating 1 Semaphore proof")
                .white()
                .bold()
        );
        let now = Instant::now();
        let proof = data.prove(pw)?;
        report_elapsed(now);
        Ok((
            Signal {
                topics: vec![topic],
                nullifier: vec![nullifier],
                proof: proof.proof,
            },
            data.verifier_data(),
        ))
    }
}
