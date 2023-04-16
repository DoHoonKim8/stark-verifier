use plonky2::plonk::{proof::ProofWithPublicInputs, circuit_data::{VerifierOnlyCircuitData, CommonCircuitData}};

pub mod plonky2_semaphore;
pub mod snark;
pub mod stark;

pub type ProofTuple<F, C, const D: usize> = (
    ProofWithPublicInputs<F, C, D>,
    VerifierOnlyCircuitData<C, D>,
    CommonCircuitData<F, D>,
);
