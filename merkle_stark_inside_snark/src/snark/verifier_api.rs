use crate::stark::recursion::ProofTuple;
use halo2_proofs::dev::MockProver;
use halo2curves::{goldilocks::fp::Goldilocks, FieldExt};
use plonky2::{field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig};
use poseidon::Spec;

use super::types::{
    self, common_data::CommonData, proof::ProofValues, verification_key::VerificationKeyValues,
};
use super::verifier_circuit::Verifier;

fn run_verifier_circuit<F: FieldExt>(
    proof: ProofValues<F, 2>,
    public_inputs: Vec<Goldilocks>,
    vk: VerificationKeyValues<F>,
    common_data: CommonData<F>,
    spec: Spec<Goldilocks, 12, 11>,
) {
    let verifier_circuit = Verifier::new(proof, public_inputs, vk, common_data, spec);
    let instance = vec![vec![]];
    let _prover = MockProver::run(22, &verifier_circuit, instance).unwrap();
    _prover.assert_satisfied()
}

/// Public API for generating Halo2 proof for Plonky2 verifier circuit
/// feed Plonky2 proof, `VerifierOnlyCircuitData`, `CommonCircuitData`
pub fn verify_inside_snark<F: FieldExt>(
    proof: ProofTuple<GoldilocksField, PoseidonGoldilocksConfig, 2>,
) {
    let (proof_with_public_inputs, vd, cd) = proof;

    // proof_with_public_inputs -> ProofValues type
    let proof = ProofValues::<F, 2>::from(proof_with_public_inputs.proof);

    let public_inputs = proof_with_public_inputs
        .public_inputs
        .iter()
        .map(|e| types::to_goldilocks(*e))
        .collect::<Vec<Goldilocks>>();
    let vk = VerificationKeyValues::from(vd.clone());
    let common_data = CommonData::from(cd);

    let spec = Spec::<Goldilocks, 12, 11>::new(8, 22);
    run_verifier_circuit(proof, public_inputs, vk, common_data, spec);
}

#[cfg(test)]
mod tests {
    use halo2curves::bn256::Fr;

    use crate::stark::mock;

    use super::verify_inside_snark;
    #[test]
    fn test_verify_dummy_proof() -> anyhow::Result<()> {
        let proof = mock::gen_dummy_proof()?;
        verify_inside_snark::<Fr>(proof);
        Ok(())
    }

    #[test]
    fn test_verify_test_proof() -> anyhow::Result<()> {
        let proof = mock::gen_test_proof()?;
        verify_inside_snark::<Fr>(proof);
        Ok(())
    }
}
