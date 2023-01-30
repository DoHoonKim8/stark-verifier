use crate::stark::recursion::ProofTuple;
use halo2_proofs::circuit::Value;
use halo2curves::goldilocks::fp::Goldilocks;
use plonky2::field::extension::Extendable;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::fri::proof::{FriInitialTreeProof, FriQueryStep};
use plonky2::hash::merkle_proofs::MerkleProof;
use plonky2::hash::merkle_tree::MerkleCap;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::plonk::config::{GenericConfig, GenericHashOut};

use super::types::{
    ExtensionFieldValue, FriInitialTreeProofValues, FriQueryRoundValues, FriQueryStepValues,
    MerkleCapValues, MerkleProofValues,
};

fn gen_merkle_cap_values(
    merkle_cap: &MerkleCap<GoldilocksField, PoseidonHash>,
) -> MerkleCapValues<Goldilocks> {
    let merkle_cap_values: Vec<[Value<Goldilocks>; 4]> = merkle_cap
        .0
        .iter()
        .map(|hash| {
            let mut cap_values = [Value::unknown(); 4];
            for (cv, h) in cap_values.iter_mut().zip(hash.to_vec()) {
                *cv = Value::known(Goldilocks::from(h.0));
            }
            cap_values
        })
        .collect();
    MerkleCapValues(merkle_cap_values)
}

fn gen_extension_field_values(
    extension_fields: Vec<<GoldilocksField as Extendable<2>>::Extension>,
) -> Vec<ExtensionFieldValue<Goldilocks, 2>> {
    extension_fields
        .iter()
        .map(|e| {
            let mut ext_values = [Value::unknown(); 2];
            for (ext, e) in ext_values.iter_mut().zip(e.0) {
                *ext = Value::known(Goldilocks::from(e.0));
            }
            ExtensionFieldValue(ext_values)
        })
        .collect()
}

fn gen_merkle_proof_values(
    merkle_proof: &MerkleProof<GoldilocksField, PoseidonHash>,
) -> MerkleProofValues<Goldilocks> {
    let siblings = merkle_proof
        .siblings
        .iter()
        .map(|hash| {
            let mut proof_values = [Value::unknown(); 4];
            for (pv, h) in proof_values.iter_mut().zip(hash.elements) {
                *pv = Value::known(Goldilocks::from(h.0));
            }
            proof_values
        })
        .collect();
    MerkleProofValues { siblings }
}

fn gen_fri_initial_tree_proof_values(
    fri_initial_tree_proof: FriInitialTreeProof<GoldilocksField, PoseidonHash>,
) -> FriInitialTreeProofValues<Goldilocks> {
    let evals_proofs = fri_initial_tree_proof
        .evals_proofs
        .iter()
        .map(|(evals, proofs)| {
            let evals_values: Vec<Value<Goldilocks>> = evals
                .iter()
                .map(|f| Value::known(Goldilocks::from(f.0)))
                .collect();
            let proofs_values = gen_merkle_proof_values(proofs);
            (evals_values, proofs_values)
        })
        .collect();
    FriInitialTreeProofValues { evals_proofs }
}

fn gen_fri_query_steps_values(
    fri_query_steps: &FriQueryStep<GoldilocksField, PoseidonHash, 2>,
) -> FriQueryStepValues<Goldilocks, 2> {
    let evals_values = gen_extension_field_values(fri_query_steps.evals.clone());
    let merkle_proof_values = gen_merkle_proof_values(&fri_query_steps.merkle_proof);
    FriQueryStepValues {
        evals: evals_values,
        merkle_proof: merkle_proof_values,
    }
}

/// Public API for generating Halo2 proof for Plonky2 verifier circuit
/// feed Plonky2 proof, `VerifierOnlyCircuitData`, `CommonCircuitData`
pub fn verify_inside_snark<C: GenericConfig<2, F = GoldilocksField, Hasher = PoseidonHash>>(
    proof: ProofTuple<GoldilocksField, C, 2>,
) {
    let (proof_with_public_inputs, vd, cd) = proof;

    // proof_with_public_inputs -> ProofValues type
    let wires_cap = gen_merkle_cap_values(&proof_with_public_inputs.proof.wires_cap);
    let plonk_zs_partial_products_cap =
        gen_merkle_cap_values(&proof_with_public_inputs.proof.plonk_zs_partial_products_cap);
    let quotient_polys_cap =
        gen_merkle_cap_values(&proof_with_public_inputs.proof.quotient_polys_cap);

    // openings
    let constants = gen_extension_field_values(proof_with_public_inputs.proof.openings.constants);
    let plonk_sigmas =
        gen_extension_field_values(proof_with_public_inputs.proof.openings.plonk_sigmas);
    let wires = gen_extension_field_values(proof_with_public_inputs.proof.openings.wires);
    let plonk_zs = gen_extension_field_values(proof_with_public_inputs.proof.openings.plonk_zs);
    let plonk_zs_next =
        gen_extension_field_values(proof_with_public_inputs.proof.openings.plonk_zs_next);
    let partial_products =
        gen_extension_field_values(proof_with_public_inputs.proof.openings.partial_products);
    let quotient_polys =
        gen_extension_field_values(proof_with_public_inputs.proof.openings.quotient_polys);

    // opening_proof
    let commit_phase_merkle_values: Vec<MerkleCapValues<Goldilocks>> = proof_with_public_inputs
        .proof
        .opening_proof
        .commit_phase_merkle_caps
        .iter()
        .map(|merkle_cap| gen_merkle_cap_values(merkle_cap))
        .collect();
    let query_round_proofs: Vec<FriQueryRoundValues<Goldilocks, 2>> = proof_with_public_inputs
        .proof
        .opening_proof
        .query_round_proofs
        .iter()
        .map(|fri_query_round| {
            let initial_trees_proof =
                gen_fri_initial_tree_proof_values(fri_query_round.initial_trees_proof.clone());
            let steps: Vec<FriQueryStepValues<Goldilocks, 2>> = fri_query_round
                .steps
                .iter()
                .map(|s| gen_fri_query_steps_values(s))
                .collect();
            FriQueryRoundValues {
                initial_trees_proof,
                steps,
            }
        })
        .collect();


}
