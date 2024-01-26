use plonky2::{
    hash::poseidon::{HALF_N_FULL_ROUNDS, N_PARTIAL_ROUNDS},
    plonk::{
        circuit_data::{CommonCircuitData, VerifierOnlyCircuitData},
        proof::ProofWithPublicInputs,
    },
};
const T: usize = 12;
const T_MINUS_ONE: usize = T - 1;
const RATE: usize = T - 4;

const R_F: usize = HALF_N_FULL_ROUNDS * 2;
const R_F_HALF: usize = R_F / 2;
const R_P: usize = N_PARTIAL_ROUNDS;

pub mod chip;
pub mod types;
// pub mod utils;
pub mod verifier_api;
pub mod verifier_circuit;

pub type ProofTuple<F, C, const D: usize> = (
    ProofWithPublicInputs<F, C, D>,
    VerifierOnlyCircuitData<C, D>,
    CommonCircuitData<F, D>,
);
