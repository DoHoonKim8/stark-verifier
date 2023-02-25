use crate::stark::merkle::{Digest, MerkleTreeCircuit, C, D, F};
use crate::stark::recursion::ProofTuple;
use anyhow::{anyhow, Result};
use plonky2::field::extension::Extendable;
use plonky2::field::types::{Field, Sample};
use plonky2::gates::noop::NoopGate;
use plonky2::hash::hash_types::RichField;
use plonky2::hash::{merkle_tree::MerkleTree, poseidon::PoseidonHash};
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
use plonky2::plonk::config::GenericConfig;
use plonky2::plonk::config::Hasher;
use plonky2::plonk::prover::prove;
use plonky2::util::timing::TimingTree;

/// Creates a dummy proof which should have `2 ** log2_size` rows.
fn dummy_proof<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>(
    config: &CircuitConfig,
    log2_size: usize,
) -> Result<ProofTuple<F, C, D>> {
    // 'size' is in degree, but we want number of noop gates. A non-zero amount of padding will be added and size will be rounded to the next power of two. To hit our target size, we go just under the previous power of two and hope padding is less than half the proof.
    let num_dummy_gates = match log2_size {
        0 => return Err(anyhow!("size must be at least 1")),
        1 => 0,
        2 => 1,
        n => (1 << (n - 1)) + 1,
    };
    let mut builder = CircuitBuilder::<F, D>::new(config.clone());
    for _ in 0..num_dummy_gates {
        builder.add_gate(NoopGate, vec![]);
    }
    builder.print_gate_counts(0);

    let data = builder.build::<C>();
    let inputs = PartialWitness::new();

    let mut timing = TimingTree::default();
    let proof = prove(&data.prover_only, &data.common, inputs, &mut timing)?;
    timing.print();
    data.verify(proof.clone())?;

    Ok((proof, data.verifier_only, data.common))
}

pub fn gen_dummy_proof() -> Result<ProofTuple<F, C, D>> {
    let config = CircuitConfig::standard_recursion_zk_config();
    let log2_size = 5;
    dummy_proof::<F, C, D>(&config, log2_size)
}

pub fn gen_recursive_proof() -> Result<ProofTuple<F, C, D>> {
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

pub fn gen_test_proof() -> Result<ProofTuple<F, C, D>> {
    let config = CircuitConfig::standard_recursion_zk_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);
    // The arithmetic circuit.
    let initial_a = builder.add_virtual_target();
    let initial_b = builder.add_virtual_target();
    let mut prev_target = initial_a;
    let mut cur_target = initial_b;
    for _ in 0..99 {
        let temp = builder.add(prev_target, cur_target);
        prev_target = cur_target;
        cur_target = temp;
    }

    // Provide initial values.
    let mut pw = PartialWitness::new();
    pw.set_target(initial_a, F::ZERO);
    pw.set_target(initial_b, F::ONE);

    let data = builder.build::<C>();
    let proof = data.prove(pw)?;

    Ok((proof, data.verifier_only, data.common))
}
