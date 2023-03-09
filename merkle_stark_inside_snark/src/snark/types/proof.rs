use crate::snark::chip::plonk::plonk_verifier_chip::PlonkVerifierChip;

use super::assigned::{
    AssignedExtensionFieldValue, AssignedFriInitialTreeProofValues, AssignedFriProofValues,
    AssignedFriQueryRoundValues, AssignedFriQueryStepValues, AssignedHashValues,
    AssignedMerkleCapValues, AssignedMerkleProofValues, AssignedOpeningSetValues,
    AssignedPolynomialCoeffsExtValues, AssignedProofValues,
};
use super::{ExtensionFieldValue, HashValues, MerkleCapValues};
use halo2_proofs::circuit::Value;
use halo2_proofs::plonk::Error;
use halo2curves::{goldilocks::fp::Goldilocks, FieldExt};
use halo2wrong::RegionCtx;
use halo2wrong_maingate::{AssignedValue, MainGateInstructions};
use itertools::Itertools;
use plonky2::hash::merkle_proofs::MerkleProof;
use plonky2::{
    field::goldilocks_field::GoldilocksField,
    fri::proof::{FriInitialTreeProof, FriQueryStep},
    hash::poseidon::PoseidonHash,
};

#[derive(Debug, Default)]
pub struct OpeningSetValues<F: FieldExt, const D: usize> {
    pub constants: Vec<ExtensionFieldValue<F, D>>,
    pub plonk_sigmas: Vec<ExtensionFieldValue<F, D>>,
    pub wires: Vec<ExtensionFieldValue<F, D>>,
    pub plonk_zs: Vec<ExtensionFieldValue<F, D>>,
    pub plonk_zs_next: Vec<ExtensionFieldValue<F, D>>,
    pub partial_products: Vec<ExtensionFieldValue<F, D>>,
    pub quotient_polys: Vec<ExtensionFieldValue<F, D>>,
}

impl OpeningSetValues<Goldilocks, 2> {
    pub fn assign(
        verifier: &PlonkVerifierChip,
        ctx: &mut RegionCtx<'_, Goldilocks>,
        opening_set_values: &Self,
    ) -> Result<AssignedOpeningSetValues<Goldilocks, 2>, Error> {
        let constants = opening_set_values
            .constants
            .iter()
            .map(|c| ExtensionFieldValue::assign(verifier, ctx, c))
            .collect::<Result<Vec<AssignedExtensionFieldValue<Goldilocks, 2>>, Error>>()?;
        let plonk_sigmas = opening_set_values
            .plonk_sigmas
            .iter()
            .map(|s| ExtensionFieldValue::assign(verifier, ctx, s))
            .collect::<Result<Vec<AssignedExtensionFieldValue<Goldilocks, 2>>, Error>>()?;
        let wires = opening_set_values
            .wires
            .iter()
            .map(|w| ExtensionFieldValue::assign(verifier, ctx, w))
            .collect::<Result<Vec<AssignedExtensionFieldValue<Goldilocks, 2>>, Error>>()?;
        let plonk_zs = opening_set_values
            .plonk_zs
            .iter()
            .map(|z| ExtensionFieldValue::assign(verifier, ctx, z))
            .collect::<Result<Vec<AssignedExtensionFieldValue<Goldilocks, 2>>, Error>>()?;
        let plonk_zs_next = opening_set_values
            .plonk_zs_next
            .iter()
            .map(|z_next| ExtensionFieldValue::assign(verifier, ctx, z_next))
            .collect::<Result<Vec<AssignedExtensionFieldValue<Goldilocks, 2>>, Error>>()?;
        let partial_products = opening_set_values
            .partial_products
            .iter()
            .map(|p| ExtensionFieldValue::assign(verifier, ctx, p))
            .collect::<Result<Vec<AssignedExtensionFieldValue<Goldilocks, 2>>, Error>>()?;
        let quotient_polys = opening_set_values
            .quotient_polys
            .iter()
            .map(|q| ExtensionFieldValue::assign(verifier, ctx, q))
            .collect::<Result<Vec<AssignedExtensionFieldValue<Goldilocks, 2>>, Error>>()?;
        Ok(AssignedOpeningSetValues {
            constants,
            plonk_sigmas,
            wires,
            plonk_zs,
            plonk_zs_next,
            partial_products,
            quotient_polys,
        })
    }
}

#[derive(Debug, Default)]
pub struct MerkleProofValues<F: FieldExt> {
    pub siblings: Vec<HashValues<F>>,
}

impl MerkleProofValues<Goldilocks> {
    pub fn assign(
        verifier: &PlonkVerifierChip,
        ctx: &mut RegionCtx<'_, Goldilocks>,
        merkle_proof_values: &Self,
    ) -> Result<AssignedMerkleProofValues<Goldilocks>, Error> {
        let siblings = merkle_proof_values
            .siblings
            .iter()
            .map(|hash_value| HashValues::assign(verifier, ctx, hash_value))
            .collect::<Result<Vec<AssignedHashValues<Goldilocks>>, Error>>()?;
        Ok(AssignedMerkleProofValues { siblings })
    }
}

impl From<MerkleProof<GoldilocksField, PoseidonHash>> for MerkleProofValues<Goldilocks> {
    fn from(value: MerkleProof<GoldilocksField, PoseidonHash>) -> Self {
        let siblings = value
            .siblings
            .iter()
            .map(|value| HashValues::from(*value))
            .collect();
        MerkleProofValues { siblings }
    }
}

#[derive(Debug, Default)]
pub struct FriInitialTreeProofValues<F: FieldExt> {
    pub evals_proofs: Vec<(Vec<Value<F>>, MerkleProofValues<F>)>,
}

impl From<FriInitialTreeProof<GoldilocksField, PoseidonHash>>
    for FriInitialTreeProofValues<Goldilocks>
{
    fn from(value: FriInitialTreeProof<GoldilocksField, PoseidonHash>) -> Self {
        let evals_proofs = value
            .evals_proofs
            .iter()
            .map(|(evals, proofs)| {
                let evals_values: Vec<Value<Goldilocks>> = evals
                    .iter()
                    .map(|f| Value::known(Goldilocks::from(f.0)))
                    .collect();
                let proofs_values = MerkleProofValues::from(proofs.clone());
                (evals_values, proofs_values)
            })
            .collect();
        FriInitialTreeProofValues { evals_proofs }
    }
}

#[derive(Debug, Default)]
pub struct FriQueryStepValues<F: FieldExt, const D: usize> {
    pub evals: Vec<ExtensionFieldValue<F, D>>,
    pub merkle_proof: MerkleProofValues<F>,
}

impl FriQueryStepValues<Goldilocks, 2> {
    pub fn assign(
        verifier: &PlonkVerifierChip,
        ctx: &mut RegionCtx<'_, Goldilocks>,
        fri_query_step_values: &Self,
    ) -> Result<AssignedFriQueryStepValues<Goldilocks, 2>, Error> {
        let evals = fri_query_step_values
            .evals
            .iter()
            .map(|v| ExtensionFieldValue::assign(verifier, ctx, v))
            .collect::<Result<Vec<AssignedExtensionFieldValue<Goldilocks, 2>>, Error>>()?;
        let merkle_proof = AssignedMerkleProofValues {
            siblings: fri_query_step_values
                .merkle_proof
                .siblings
                .iter()
                .map(|hash_value| HashValues::assign(verifier, ctx, hash_value))
                .collect::<Result<Vec<AssignedHashValues<Goldilocks>>, Error>>()?,
        };
        Ok(AssignedFriQueryStepValues {
            evals,
            merkle_proof,
        })
    }
}

impl From<FriQueryStep<GoldilocksField, PoseidonHash, 2>> for FriQueryStepValues<Goldilocks, 2> {
    fn from(value: FriQueryStep<GoldilocksField, PoseidonHash, 2>) -> Self {
        let evals_values = value
            .evals
            .iter()
            .map(|e| ExtensionFieldValue::from(e.0))
            .collect();
        let merkle_proof_values = MerkleProofValues::from(value.merkle_proof.clone());
        FriQueryStepValues {
            evals: evals_values,
            merkle_proof: merkle_proof_values,
        }
    }
}

#[derive(Debug, Default)]
pub struct FriQueryRoundValues<F: FieldExt, const D: usize> {
    pub initial_trees_proof: FriInitialTreeProofValues<F>,
    pub steps: Vec<FriQueryStepValues<F, D>>,
}

impl FriQueryRoundValues<Goldilocks, 2> {
    pub fn assign(
        verifier: &PlonkVerifierChip,
        ctx: &mut RegionCtx<'_, Goldilocks>,
        fri_query_round_values: &Self,
    ) -> Result<AssignedFriQueryRoundValues<Goldilocks, 2>, Error> {
        let main_gate = verifier.main_gate();
        let values = fri_query_round_values
            .initial_trees_proof
            .evals_proofs
            .iter()
            .map(|(values, _)| {
                values
                    .iter()
                    .map(|v| main_gate.assign_value(ctx, *v))
                    .collect()
            })
            .collect::<Result<Vec<Vec<AssignedValue<Goldilocks>>>, Error>>()?;

        let merkle_proofs = fri_query_round_values
            .initial_trees_proof
            .evals_proofs
            .iter()
            .map(|(_, merkle_proof_values)| {
                MerkleProofValues::assign(verifier, ctx, merkle_proof_values)
            })
            .collect::<Result<Vec<AssignedMerkleProofValues<Goldilocks>>, Error>>()?;
        let evals_proofs = values
            .into_iter()
            .zip_eq(merkle_proofs.into_iter())
            .collect_vec();
        let steps = fri_query_round_values
            .steps
            .iter()
            .map(|fri_query_step_values| {
                FriQueryStepValues::assign(verifier, ctx, fri_query_step_values)
            })
            .collect::<Result<Vec<AssignedFriQueryStepValues<Goldilocks, 2>>, Error>>()?;
        Ok(AssignedFriQueryRoundValues {
            initial_trees_proof: AssignedFriInitialTreeProofValues { evals_proofs },
            steps,
        })
    }
}

#[derive(Debug, Default)]
pub struct PolynomialCoeffsExtValues<F: FieldExt, const D: usize>(
    pub Vec<ExtensionFieldValue<F, D>>,
);

impl PolynomialCoeffsExtValues<Goldilocks, 2> {
    pub fn assign(
        verifier: &PlonkVerifierChip,
        ctx: &mut RegionCtx<'_, Goldilocks>,
        polynomial_coeffs_ext_values: &Self,
    ) -> Result<AssignedPolynomialCoeffsExtValues<Goldilocks, 2>, Error> {
        Ok(AssignedPolynomialCoeffsExtValues(
            polynomial_coeffs_ext_values
                .0
                .iter()
                .map(|v| ExtensionFieldValue::assign(verifier, ctx, v))
                .collect::<Result<Vec<AssignedExtensionFieldValue<Goldilocks, 2>>, Error>>()?,
        ))
    }
}

#[derive(Debug, Default)]
pub struct FriProofValues<F: FieldExt, const D: usize> {
    pub commit_phase_merkle_cap_values: Vec<MerkleCapValues<F>>,
    pub query_round_proofs: Vec<FriQueryRoundValues<F, D>>,
    pub final_poly: PolynomialCoeffsExtValues<F, D>,
    pub pow_witness: Value<F>,
}

impl FriProofValues<Goldilocks, 2> {
    pub fn assign(
        verifier: &PlonkVerifierChip,
        ctx: &mut RegionCtx<'_, Goldilocks>,
        fri_proof_values: &Self,
    ) -> Result<AssignedFriProofValues<Goldilocks, 2>, Error> {
        let main_gate = verifier.main_gate();
        let commit_phase_merkle_cap_values = fri_proof_values
            .commit_phase_merkle_cap_values
            .iter()
            .map(|merkle_cap_values| MerkleCapValues::assign(verifier, ctx, merkle_cap_values))
            .collect::<Result<Vec<AssignedMerkleCapValues<Goldilocks>>, Error>>()?;
        let query_round_proofs = fri_proof_values
            .query_round_proofs
            .iter()
            .map(|fri_query_round_values| {
                FriQueryRoundValues::assign(verifier, ctx, fri_query_round_values)
            })
            .collect::<Result<Vec<AssignedFriQueryRoundValues<Goldilocks, 2>>, Error>>()?;
        let final_poly =
            PolynomialCoeffsExtValues::assign(verifier, ctx, &fri_proof_values.final_poly)?;
        let pow_witness = main_gate
            .assign_value(ctx, fri_proof_values.pow_witness)
            .unwrap();
        Ok(AssignedFriProofValues {
            commit_phase_merkle_cap_values,
            query_round_proofs,
            final_poly,
            pow_witness,
        })
    }
}

#[derive(Debug, Default)]
pub struct ProofValues<F: FieldExt, const D: usize> {
    pub wires_cap: MerkleCapValues<F>,
    pub plonk_zs_partial_products_cap: MerkleCapValues<F>,
    pub quotient_polys_cap: MerkleCapValues<F>,

    pub openings: OpeningSetValues<F, D>,
    pub opening_proof: FriProofValues<F, D>,
}

impl ProofValues<Goldilocks, 2> {
    pub fn assign(
        verifier: &PlonkVerifierChip,
        ctx: &mut RegionCtx<'_, Goldilocks>,
        proof: &Self,
    ) -> Result<AssignedProofValues<Goldilocks, 2>, Error> {
        let wires_cap = MerkleCapValues::assign(verifier, ctx, &proof.wires_cap)?;
        let plonk_zs_partial_products_cap =
            MerkleCapValues::assign(verifier, ctx, &proof.plonk_zs_partial_products_cap)?;
        let quotient_polys_cap = MerkleCapValues::assign(verifier, ctx, &proof.quotient_polys_cap)?;
        let openings = OpeningSetValues::assign(verifier, ctx, &proof.openings)?;
        let opening_proof = FriProofValues::assign(verifier, ctx, &proof.opening_proof)?;
        Ok(AssignedProofValues {
            wires_cap,
            plonk_zs_partial_products_cap,
            quotient_polys_cap,
            openings,
            opening_proof,
        })
    }
}
