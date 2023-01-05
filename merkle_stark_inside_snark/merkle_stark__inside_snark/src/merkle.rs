use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::{HashOut, HashOutTarget};
use plonky2::hash::merkle_proofs::{MerkleProof, MerkleProofTarget};
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::iop::target::Target;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;

pub const D: usize = 2;
pub type F = GoldilocksField;
pub type Digest = [F; 4];

#[derive(Clone)]
pub struct MerkleTreeCircuitTargets {
    merkle_root: HashOutTarget,
    merkle_proof: MerkleProofTarget,
    private_key: [Target; 4],
    public_key_index: Target,
    tree_height: usize,
}

pub struct MerkleTreeCircuit {
    targets: MerkleTreeCircuitTargets,
}

impl MerkleTreeCircuit {
    pub fn construct(targets: MerkleTreeCircuitTargets) -> Self {
        Self { targets }
    }

    pub fn tree_height(&self) -> usize {
        self.targets.tree_height
    }

    pub fn targets(&self) -> MerkleTreeCircuitTargets {
        self.targets.clone()
    }

    pub fn configure(
        builder: &mut CircuitBuilder<F, D>,
        tree_height: usize,
    ) -> MerkleTreeCircuitTargets {
        let merkle_root = builder.add_virtual_hash();
        builder.register_public_inputs(&merkle_root.elements);

        let merkle_proof = MerkleProofTarget {
            siblings: builder.add_virtual_hashes(tree_height),
        };

        let private_key: [Target; 4] = builder.add_virtual_targets(4).try_into().unwrap();
        let public_key_index = builder.add_virtual_target();
        let public_key_index_bits = builder.split_le(public_key_index, tree_height);
        let zero = builder.zero();
        builder.verify_merkle_proof::<PoseidonHash>(
            [private_key, [zero; 4]].concat(),
            &public_key_index_bits,
            merkle_root,
            &merkle_proof,
        );

        MerkleTreeCircuitTargets {
            merkle_root,
            merkle_proof,
            private_key,
            public_key_index,
            tree_height,
        }
    }

    pub fn assign_targets(
        &self,
        pw: &mut PartialWitness<F>,
        merkle_root: HashOut<F>,
        merkle_proof: MerkleProof<F, PoseidonHash>,
        private_key: Digest,
        public_key_index: usize,
        config: MerkleTreeCircuitTargets,
    ) {
        let MerkleTreeCircuitTargets {
            merkle_root: merkle_root_target,
            merkle_proof: merkle_proof_target,
            private_key: private_key_target,
            public_key_index: public_key_index_target,
            tree_height,
        } = config;

        assert_eq!(
            tree_height,
            merkle_proof.siblings.len(),
            "merkle proof length \\neq tree_height"
        );

        pw.set_hash_target(merkle_root_target, merkle_root);
        for (ht, value) in merkle_proof_target
            .siblings
            .into_iter()
            .zip(merkle_proof.siblings)
        {
            pw.set_hash_target(ht, value);
        }

        for (target, value) in private_key_target.into_iter().zip(private_key) {
            pw.set_target(target, value);
        }

        pw.set_target(
            public_key_index_target,
            F::from_canonical_usize(public_key_index),
        );
    }
}

#[cfg(test)]
mod tests {
    use crate::merkle::{Digest, MerkleTreeCircuit, D, F};
    use anyhow::Result;
    use plonky2::field::types::{Field, Sample};
    use plonky2::hash::{merkle_tree::MerkleTree, poseidon::PoseidonHash};
    use plonky2::iop::witness::PartialWitness;
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
    use plonky2::plonk::config::{Hasher, PoseidonGoldilocksConfig};
    use std::time::Instant;

    fn report_elapsed(now: Instant) {
        println!("{}", format!("Took {} seconds", now.elapsed().as_secs()));
    }

    #[test]
    fn merkle_test() -> Result<()> {
        let n = 1 << 10;
        let private_keys: Vec<Digest> = (0..n).map(|_| F::rand_array()).collect();
        let public_keys: Vec<Vec<F>> = private_keys
            .iter()
            .map(|&sk| {
                PoseidonHash::hash_no_pad(&[sk, [F::ZERO; 4]].concat())
                    .elements
                    .to_vec()
            })
            .collect();
        let merkle_tree: MerkleTree<F, PoseidonHash> = MerkleTree::new(public_keys, 0);

        let public_key_index = 12;
        let config = CircuitConfig::standard_recursion_zk_config();
        let mut builder = CircuitBuilder::new(config);
        let mut pw: PartialWitness<F> = PartialWitness::new();

        let tree_height = 10;
        let circuit_config = MerkleTreeCircuit::configure(&mut builder, tree_height);
        let circuit = MerkleTreeCircuit::construct(circuit_config);
        circuit.assign_targets(
            &mut pw,
            merkle_tree.cap.0[0],
            merkle_tree.prove(public_key_index),
            private_keys[public_key_index],
            public_key_index,
            circuit.targets.clone(),
        );

        let data: CircuitData<F, PoseidonGoldilocksConfig, D> = builder.build();
        let now = Instant::now();
        let proof = data.prove(pw)?;
        report_elapsed(now);

        data.verify(proof)
    }
}
