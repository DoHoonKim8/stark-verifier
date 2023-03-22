use crate::stark::recursion::ProofTuple;
use halo2_proofs::dev::MockProver;
use halo2curves::{goldilocks::fp::Goldilocks, FieldExt};
use plonky2::{field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig};
use poseidon::Spec;

use super::types::{
    self,
    common_data::CommonData,
    proof::{
        FriInitialTreeProofValues, FriProofValues, FriQueryRoundValues, FriQueryStepValues,
        OpeningSetValues, PolynomialCoeffsExtValues, ProofValues,
    },
    to_extension_field_values,
    verification_key::VerificationKeyValues,
    MerkleCapValues,
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
    let _prover = MockProver::run(18, &verifier_circuit, instance).unwrap();
    _prover.assert_satisfied()
}

/// Public API for generating Halo2 proof for Plonky2 verifier circuit
/// feed Plonky2 proof, `VerifierOnlyCircuitData`, `CommonCircuitData`
pub fn verify_inside_snark<F: FieldExt>(
    proof: ProofTuple<GoldilocksField, PoseidonGoldilocksConfig, 2>,
) {
    let (proof_with_public_inputs, vd, cd) = proof;

    // proof_with_public_inputs -> ProofValues type
    let wires_cap = MerkleCapValues::from(proof_with_public_inputs.proof.wires_cap.clone());
    let plonk_zs_partial_products_cap = MerkleCapValues::from(
        proof_with_public_inputs
            .proof
            .plonk_zs_partial_products_cap
            .clone(),
    );
    let quotient_polys_cap =
        MerkleCapValues::from(proof_with_public_inputs.proof.quotient_polys_cap.clone());

    // openings
    let constants = to_extension_field_values(proof_with_public_inputs.proof.openings.constants);
    let plonk_sigmas =
        to_extension_field_values(proof_with_public_inputs.proof.openings.plonk_sigmas);
    let wires = to_extension_field_values(proof_with_public_inputs.proof.openings.wires);
    let plonk_zs = to_extension_field_values(proof_with_public_inputs.proof.openings.plonk_zs);
    let plonk_zs_next =
        to_extension_field_values(proof_with_public_inputs.proof.openings.plonk_zs_next);
    let partial_products =
        to_extension_field_values(proof_with_public_inputs.proof.openings.partial_products);
    let quotient_polys =
        to_extension_field_values(proof_with_public_inputs.proof.openings.quotient_polys);
    let openings = OpeningSetValues {
        constants,
        plonk_sigmas,
        wires,
        plonk_zs,
        plonk_zs_next,
        partial_products,
        quotient_polys,
    };

    // opening_proof
    let commit_phase_merkle_cap_values: Vec<MerkleCapValues<F>> = proof_with_public_inputs
        .proof
        .opening_proof
        .commit_phase_merkle_caps
        .iter()
        .map(|merkle_cap| MerkleCapValues::from(merkle_cap.clone()))
        .collect();
    let query_round_proofs: Vec<FriQueryRoundValues<F, 2>> = proof_with_public_inputs
        .proof
        .opening_proof
        .query_round_proofs
        .iter()
        .map(|fri_query_round| {
            let initial_trees_proof =
                FriInitialTreeProofValues::from(fri_query_round.initial_trees_proof.clone());
            let steps: Vec<FriQueryStepValues<F, 2>> = fri_query_round
                .steps
                .iter()
                .map(|s| FriQueryStepValues::from(s.clone()))
                .collect();
            FriQueryRoundValues {
                initial_trees_proof,
                steps,
            }
        })
        .collect();
    let final_poly = PolynomialCoeffsExtValues(to_extension_field_values(
        proof_with_public_inputs
            .proof
            .opening_proof
            .final_poly
            .coeffs,
    ));
    let pow_witness =
        types::to_goldilocks(proof_with_public_inputs.proof.opening_proof.pow_witness);
    let opening_proof = FriProofValues {
        commit_phase_merkle_cap_values,
        query_round_proofs,
        final_poly,
        pow_witness,
    };

    let proof = ProofValues {
        wires_cap,
        plonk_zs_partial_products_cap,
        quotient_polys_cap,

        openings,
        opening_proof,
    };

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
