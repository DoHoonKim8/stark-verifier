use plonky2::hash::{
    hashing::SPONGE_WIDTH,
    poseidon::{HALF_N_FULL_ROUNDS, N_PARTIAL_ROUNDS},
};
const T: usize = SPONGE_WIDTH;
const T_MINUS_ONE: usize = SPONGE_WIDTH - 1;
const RATE: usize = SPONGE_WIDTH - 4;

const R_F: usize = HALF_N_FULL_ROUNDS * 2;
const R_F_HALF: usize = R_F / 2;
const R_P: usize = N_PARTIAL_ROUNDS;

pub mod chip;
pub mod types;
pub mod utils;
pub mod verifier_api;
pub mod verifier_circuit;
