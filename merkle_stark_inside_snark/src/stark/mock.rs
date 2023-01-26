use crate::stark::merkle::{Digest, MerkleTreeCircuit, C, D, F};
use crate::stark::recursion::ProofTuple;
use anyhow::Result;
use plonky2::field::types::{Field, Sample};
use plonky2::hash::{merkle_tree::MerkleTree, poseidon::PoseidonHash};
use plonky2::iop::witness::PartialWitness;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
use plonky2::plonk::config::Hasher;

pub fn gen_mock_proof() -> Result<ProofTuple<F, C, D>> {
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
    let mut builder = CircuitBuilder::new(config.clone());
    let mut pw: PartialWitness<F> = PartialWitness::new();

    let tree_height = 10;
    let targets = MerkleTreeCircuit::configure(&mut builder, tree_height);
    let circuit = MerkleTreeCircuit::construct(targets);
    circuit.assign_targets(
        &mut pw,
        merkle_tree.cap.0[0],
        merkle_tree.prove(public_key_index),
        private_keys[public_key_index],
        public_key_index,
        circuit.targets(),
    );

    let data: CircuitData<F, C, D> = builder.build();
    let proof = data.prove(pw)?;
    let inner = (proof, data.verifier_only, data.common);
    let public_key_index2 = 21;
    MerkleTreeCircuit::recursive_proof::<C, C>(
        &inner,
        &config,
        None,
        tree_height,
        &merkle_tree,
        public_key_index2,
        private_keys[public_key_index2],
    )
}
