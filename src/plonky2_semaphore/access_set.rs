use std::time::Instant;

use anyhow::Result;
use colored::Colorize;
use plonky2::field::types::Field;
use plonky2::fri::reduction_strategies::FriReductionStrategy;
use plonky2::fri::FriConfig;
use plonky2::hash::merkle_proofs::MerkleProofTarget;
use plonky2::hash::merkle_tree::MerkleTree;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::iop::target::Target;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, VerifierCircuitData};
use plonky2::plonk::config::Hasher;
use plonky2::plonk::proof::ProofWithPublicInputs;

use crate::snark::bn245_poseidon::plonky2_config::standard_stark_verifier_config;
use crate::snark::verifier_api::verify_inside_snark;

use super::report_elapsed;
use super::signal::{Digest, Signal, C, F};
use super::wrapper::WrapperCircuit;

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

        let proof = ProofWithPublicInputs {
            proof: signal.proof,
            public_inputs,
        };
        // Perform another recursive proof to change PoseidonGoldilocksConfig to Bn254PoseidonGoldilocksConfig
        let wrapper_circuit = WrapperCircuit::new(standard_stark_verifier_config(), &verifier_data);
        let wrapped_proof = wrapper_circuit.prove(&proof).unwrap();
        verify_inside_snark((
            wrapped_proof,
            wrapper_circuit.data.verifier_only.clone(),
            wrapper_circuit.data.common.clone(),
        ));
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
        println!("{}", format!("Generating 1 Semaphore proof").white().bold());
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

    pub fn test_membership_proof(
        &self,
        private_key: Digest,
        public_key_index: usize,
    ) -> Result<()> {
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
                reduction_strategy: FriReductionStrategy::ConstantArityBits(3, 5), // 3, 5
                num_query_rounds: 28,                                              // 28
            },
        };

        let mut builder = CircuitBuilder::new(config);
        let mut pw = PartialWitness::new();

        let merkle_root = builder.add_virtual_hash();
        builder.register_public_inputs(&merkle_root.elements);

        // Merkle proof
        let merkle_proof_target = MerkleProofTarget {
            siblings: builder.add_virtual_hashes(self.tree_height()),
        };

        // Verify public key Merkle proof.
        let private_key_target: [Target; 4] = builder.add_virtual_targets(4).try_into().unwrap();
        let public_key_index_target = builder.add_virtual_target();
        let public_key_index_bits = builder.split_le(public_key_index_target, self.tree_height());
        let zero = builder.zero();
        builder.verify_merkle_proof::<PoseidonHash>(
            [private_key_target, [zero; 4]].concat(),
            &public_key_index_bits,
            merkle_root,
            &merkle_proof_target,
        );

        pw.set_hash_target(merkle_root, self.0.cap.0[0]);
        pw.set_target_arr(private_key_target, private_key);
        pw.set_target(
            public_key_index_target,
            F::from_canonical_usize(public_key_index),
        );
        let merkle_proof = self.0.prove(public_key_index);
        for (ht, h) in merkle_proof_target
            .siblings
            .into_iter()
            .zip(merkle_proof.siblings)
        {
            pw.set_hash_target(ht, h);
        }

        let data = builder.build::<C>();
        println!("{}", format!("Generating membership proof").white().bold());
        let now = Instant::now();
        let proof = data.prove(pw)?;
        report_elapsed(now);
        println!("{}", format!("Verifying membership proof").white().bold());
        let now = Instant::now();
        data.verify(proof)?;
        report_elapsed(now);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use colored::Colorize;
    use plonky2::field::types::{Field, Sample};
    use plonky2::hash::merkle_tree::MerkleTree;
    use plonky2::hash::poseidon::PoseidonHash;
    use plonky2::plonk::config::Hasher;

    use crate::plonky2_semaphore::access_set::AccessSet;
    use crate::plonky2_semaphore::signal::{Digest, F};

    #[test]
    fn test_semaphore() -> Result<()> {
        for pow in 20..26 {
            let n = 1 << pow;
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

            let i = 12;
            println!(
                "{}",
                format!("Testing membership proof in a group size 2^{pow}")
                    .white()
                    .bold()
            );
            access_set.test_membership_proof(private_keys[i], i)?;
        }
        Ok(())
    }
}
