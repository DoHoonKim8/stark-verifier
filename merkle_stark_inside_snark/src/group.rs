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
    pub fn gen_keys(tree_height: usize) -> (Vec<Digest>, Vec<Vec<F>>) {
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
        (private_keys, public_keys)
    }

    // Generates dummy Merkle tree
    pub fn new(public_keys: &Vec<Vec<F>>) -> Self {
        Self(MerkleTree::new(public_keys.clone(), 0))
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

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use lazy_static::lazy_static;
    use plonky2::field::types::Field;
    use plonky2::hash::poseidon::PoseidonHash;
    use plonky2::plonk::config::Hasher;

    use crate::group::Group;
    use crate::merkle::Digest;
    use crate::merkle::F;

    const HEIGHT: usize = 10;
    lazy_static! {
        static ref KEYS: (Vec<Digest>, Vec<Vec<F>>) = Group::gen_keys(HEIGHT);
        static ref GROUP: Group = Group::new(&KEYS.1);
    }

    #[test]
    fn membership_test() -> Result<()> {
        let public_key_index = 12;
        let private_key = KEYS.0[public_key_index];
        let (data, proof) = GROUP.prove_membership(public_key_index, private_key);
        GROUP.verify_proof(data, proof)
    }

    #[test]
    /// TODO : Handle error
    fn fake_membership_test() -> Result<()> {
        let fake_key_index = 12;
        let fake_private_key =
            PoseidonHash::hash_no_pad(&[KEYS.0[fake_key_index], [F::ZERO; 4]].concat()).elements;
        assert_ne!(KEYS.0[fake_key_index], fake_private_key);
        let (data, proof) = GROUP.prove_membership(fake_key_index, fake_private_key);
        GROUP.verify_proof(data, proof)
    }
}
