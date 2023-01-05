use crate::merkle::{Digest, MerkleTreeCircuit, C, D, F};
use anyhow::Result;
use plonky2::field::types::Field;
use plonky2::plonk::config::Hasher;
use plonky2::{
    field::types::Sample,
    hash::{merkle_tree::MerkleTree, poseidon::PoseidonHash},
    iop::witness::PartialWitness,
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData},
        proof::ProofWithPublicInputs,
    },
};

pub struct Group(MerkleTree<F, PoseidonHash>);

impl Group {
    // Generates dummy Merkle tree
    pub fn new(tree_height: usize) -> Self {
        let n = 1 << tree_height;
        let private_keys: Vec<Digest> = (0..n).map(|_| F::rand_array()).collect();
        let public_keys: Vec<Vec<F>> = private_keys
            .iter()
            .map(|&sk| {
                PoseidonHash::hash_no_pad(&[sk, [F::ZERO; 4]].concat())
                    .elements
                    .to_vec()
            })
            .collect();
        Self(MerkleTree::new(public_keys, 0))
    }

    pub fn tree_height(&self) -> usize {
        self.0.leaves.len().trailing_zeros() as usize
    }

    pub fn prove_membership(
        &self,
        public_key_index: usize,
        private_key: Digest,
    ) -> (CircuitData<F, C, D>, ProofWithPublicInputs<F, C, D>) {
        let config = CircuitConfig::standard_recursion_zk_config();
        let mut builder = CircuitBuilder::new(config);
        let mut pw: PartialWitness<F> = PartialWitness::new();

        let tree_height = self.tree_height();
        let targets = MerkleTreeCircuit::configure(&mut builder, tree_height);
        let merkle_tree_circuit = MerkleTreeCircuit::construct(targets);
        merkle_tree_circuit.assign_targets(
            &mut pw,
            self.0.cap.0[0],
            self.0.prove(public_key_index),
            private_key,
            public_key_index,
            merkle_tree_circuit.targets(),
        );

        let data: CircuitData<F, C, D> = builder.build();
        let proof = data.prove(pw).unwrap();
        (data, proof)
    }

    pub fn verify_proof(
        &self,
        data: CircuitData<F, C, D>,
        proof: ProofWithPublicInputs<F, C, D>,
    ) -> Result<()> {
        data.verify(proof)
    }
}
