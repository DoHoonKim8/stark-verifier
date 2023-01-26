use crate::stark::merkle::{D, F};
use plonky2::plonk::config::GenericConfig;
use plonky2::plonk::proof::ProofWithPublicInputs;

/// Public API for generating Halo2 proof for Plonky2 verifier circuit
/// feed Plonky2 proof, `VerifierOnlyCircuitData`, `CommonCircuitData`
pub fn verify_inside_snark<C: GenericConfig<D, F = F>>(proof: ProofWithPublicInputs<F, C, D>) {
    todo!()
}
