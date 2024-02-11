use std::fmt::Debug;

use halo2_proofs::halo2curves::bn256::Fr;
use plonky2::{
    field::{extension::quadratic::QuadraticExtension, goldilocks_field::GoldilocksField},
    fri::{reduction_strategies::FriReductionStrategy, FriConfig},
    hash::{
        hash_types::HashOut,
        hashing::{compress, hash_n_to_hash_no_pad, PlonkyPermutation, SPONGE_WIDTH},
        poseidon::PoseidonHash,
    },
    plonk::{
        circuit_data::CircuitConfig,
        config::{GenericConfig, Hasher},
    },
};

use super::{
    constants::T_BN254_POSEIDON,
    native::{decode_fe, encode_fe, permute_bn254_poseidon_native},
};

#[derive(Copy, Clone, Default, Debug, PartialEq)]
pub struct Bn254PoseidonPermutation {
    state: [GoldilocksField; SPONGE_WIDTH],
}

impl Bn254PoseidonPermutation {
    pub fn new(state: [GoldilocksField; SPONGE_WIDTH]) -> Self {
        Self { state }
    }
}

trait Permuter: Sized {
    fn permute(input: [Self; SPONGE_WIDTH]) -> [Self; SPONGE_WIDTH];
}

impl PlonkyPermutation<GoldilocksField> for Bn254PoseidonPermutation {
    fn permute(input: [GoldilocksField; SPONGE_WIDTH]) -> [GoldilocksField; SPONGE_WIDTH] {
        let mut encoded_state = input
            .chunks(3)
            .map(|x| encode_fe(x.try_into().unwrap()))
            .collect::<Vec<_>>();
        encoded_state.resize(T_BN254_POSEIDON, Fr::from(0u64));
        let mut state: [Fr; T_BN254_POSEIDON] = encoded_state.try_into().unwrap();
        permute_bn254_poseidon_native(&mut state);
        let decoded_state =
            state.iter().flat_map(|x| decode_fe(*x)).collect::<Vec<_>>()[0..SPONGE_WIDTH].to_vec();
        decoded_state.try_into().unwrap()
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Bn254PoseidonHash;
impl Hasher<GoldilocksField> for Bn254PoseidonHash {
    const HASH_SIZE: usize = 4 * 8;
    type Hash = HashOut<GoldilocksField>;
    type Permutation = Bn254PoseidonPermutation;

    fn hash_no_pad(input: &[GoldilocksField]) -> Self::Hash {
        hash_n_to_hash_no_pad::<GoldilocksField, Self::Permutation>(input)
    }
    fn two_to_one(left: Self::Hash, right: Self::Hash) -> Self::Hash {
        compress::<GoldilocksField, Self::Permutation>(left, right)
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct Bn254PoseidonGoldilocksConfig;
impl GenericConfig<2> for Bn254PoseidonGoldilocksConfig {
    type F = GoldilocksField;
    type FE = QuadraticExtension<Self::F>;
    type Hasher = Bn254PoseidonHash;
    type InnerHasher = PoseidonHash;
}

// If you use recursive proof in the plonky2's circuit, use this config for the inner circuit.
pub fn standard_inner_stark_verifier_config() -> CircuitConfig {
    CircuitConfig {
        fri_config: FriConfig {
            rate_bits: 3,
            cap_height: 4,
            proof_of_work_bits: 16,
            reduction_strategy: FriReductionStrategy::ConstantArityBits(1, 5),
            num_query_rounds: 28,
        },
        ..CircuitConfig::standard_recursion_config()
    }
}

// Use this config for the outer circuit.
pub fn standard_stark_verifier_config() -> CircuitConfig {
    let inner_config = standard_inner_stark_verifier_config();
    CircuitConfig {
        fri_config: FriConfig {
            rate_bits: 3,
            cap_height: 0,
            proof_of_work_bits: 16,
            reduction_strategy: FriReductionStrategy::ConstantArityBits(1, 5),
            num_query_rounds: 28,
        },
        ..inner_config
    }
}
