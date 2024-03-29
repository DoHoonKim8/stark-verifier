use crate::plonky2_verifier::bn245_poseidon::plonky2_config::{
    Bn254PoseidonGoldilocksConfig, Bn254PoseidonHash,
};
use crate::plonky2_verifier::chip::goldilocks_chip::{GoldilocksChip, GoldilocksChipConfig};
use crate::plonky2_verifier::chip::native_chip::utils::goldilocks_to_fe;

use super::assigned::{
    AssignedExtensionFieldValue, AssignedFriInitialTreeProofValues, AssignedFriProofValues,
    AssignedFriQueryRoundValues, AssignedFriQueryStepValues, AssignedHashValues,
    AssignedMerkleCapValues, AssignedMerkleProofValues, AssignedOpeningSetValues,
    AssignedPolynomialCoeffsExtValues,
};
use super::{
    to_extension_field_values, to_goldilocks, ExtensionFieldValue, HashValues, MerkleCapValues,
};
use crate::plonky2_verifier::context::RegionCtx;
use halo2_proofs::circuit::Value;
use halo2_proofs::halo2curves::ff::PrimeField;
use halo2_proofs::plonk::Error;
use halo2wrong_maingate::AssignedValue;
use itertools::Itertools;
use plonky2::field::extension::quadratic::QuadraticExtension;
use plonky2::field::polynomial::PolynomialCoeffs;
use plonky2::field::types::Field;
use plonky2::fri::proof::{FriProof, FriQueryRound};
use plonky2::hash::merkle_proofs::MerkleProof;
use plonky2::plonk::proof::{OpeningSet, Proof};
use plonky2::{
    field::goldilocks_field::GoldilocksField,
    fri::proof::{FriInitialTreeProof, FriQueryStep},
};

#[derive(Clone, Debug, Default)]
pub struct OpeningSetValues<F: PrimeField, const D: usize> {
    pub constants: Vec<ExtensionFieldValue<F, D>>,
    pub plonk_sigmas: Vec<ExtensionFieldValue<F, D>>,
    pub wires: Vec<ExtensionFieldValue<F, D>>,
    pub plonk_zs: Vec<ExtensionFieldValue<F, D>>,
    pub plonk_zs_next: Vec<ExtensionFieldValue<F, D>>,
    pub partial_products: Vec<ExtensionFieldValue<F, D>>,
    pub quotient_polys: Vec<ExtensionFieldValue<F, D>>,
}

impl<F: PrimeField> From<OpeningSet<GoldilocksField, 2>> for OpeningSetValues<F, 2> {
    fn from(value: OpeningSet<GoldilocksField, 2>) -> Self {
        Self {
            constants: to_extension_field_values(value.constants),
            plonk_sigmas: to_extension_field_values(value.plonk_sigmas),
            wires: to_extension_field_values(value.wires),
            plonk_zs: to_extension_field_values(value.plonk_zs),
            plonk_zs_next: to_extension_field_values(value.plonk_zs_next),
            partial_products: to_extension_field_values(value.partial_products),
            quotient_polys: to_extension_field_values(value.quotient_polys),
        }
    }
}

impl<F: PrimeField, const D: usize> OpeningSetValues<F, D> {
    pub fn assign(
        config: &GoldilocksChipConfig<F>,
        ctx: &mut RegionCtx<'_, F>,
        opening_set_values: &Self,
    ) -> Result<AssignedOpeningSetValues<F, D>, Error> {
        let constants = opening_set_values
            .constants
            .iter()
            .map(|c| ExtensionFieldValue::assign(config, ctx, c))
            .collect::<Result<Vec<AssignedExtensionFieldValue<F, D>>, Error>>()?;
        let plonk_sigmas = opening_set_values
            .plonk_sigmas
            .iter()
            .map(|s| ExtensionFieldValue::assign(config, ctx, s))
            .collect::<Result<Vec<AssignedExtensionFieldValue<F, D>>, Error>>()?;
        let wires = opening_set_values
            .wires
            .iter()
            .map(|w| ExtensionFieldValue::assign(config, ctx, w))
            .collect::<Result<Vec<AssignedExtensionFieldValue<F, D>>, Error>>()?;
        let plonk_zs = opening_set_values
            .plonk_zs
            .iter()
            .map(|z| ExtensionFieldValue::assign(config, ctx, z))
            .collect::<Result<Vec<AssignedExtensionFieldValue<F, D>>, Error>>()?;
        let plonk_zs_next = opening_set_values
            .plonk_zs_next
            .iter()
            .map(|z_next| ExtensionFieldValue::assign(config, ctx, z_next))
            .collect::<Result<Vec<AssignedExtensionFieldValue<F, D>>, Error>>()?;
        let partial_products = opening_set_values
            .partial_products
            .iter()
            .map(|p| ExtensionFieldValue::assign(config, ctx, p))
            .collect::<Result<Vec<AssignedExtensionFieldValue<F, D>>, Error>>()?;
        let quotient_polys = opening_set_values
            .quotient_polys
            .iter()
            .map(|q| ExtensionFieldValue::assign(config, ctx, q))
            .collect::<Result<Vec<AssignedExtensionFieldValue<F, D>>, Error>>()?;
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

#[derive(Clone, Debug, Default)]
pub struct MerkleProofValues<F: PrimeField> {
    pub siblings: Vec<HashValues<F>>,
}

impl<F: PrimeField> MerkleProofValues<F> {
    pub fn assign(
        config: &GoldilocksChipConfig<F>,
        ctx: &mut RegionCtx<'_, F>,
        merkle_proof_values: &Self,
    ) -> Result<AssignedMerkleProofValues<F>, Error> {
        let siblings = merkle_proof_values
            .siblings
            .iter()
            .map(|hash_value| HashValues::assign(config, ctx, hash_value))
            .collect::<Result<Vec<AssignedHashValues<F>>, Error>>()?;
        Ok(AssignedMerkleProofValues { siblings })
    }
}

impl<F: PrimeField> From<MerkleProof<GoldilocksField, Bn254PoseidonHash>> for MerkleProofValues<F> {
    fn from(value: MerkleProof<GoldilocksField, Bn254PoseidonHash>) -> Self {
        let siblings = value
            .siblings
            .iter()
            .map(|value| HashValues::from(*value))
            .collect();
        MerkleProofValues { siblings }
    }
}

#[derive(Clone, Debug, Default)]
pub struct FriInitialTreeProofValues<F: PrimeField> {
    pub evals_proofs: Vec<(Vec<GoldilocksField>, MerkleProofValues<F>)>,
}

impl<F: PrimeField> From<FriInitialTreeProof<GoldilocksField, Bn254PoseidonHash>>
    for FriInitialTreeProofValues<F>
{
    fn from(value: FriInitialTreeProof<GoldilocksField, Bn254PoseidonHash>) -> Self {
        let evals_proofs = value
            .evals_proofs
            .iter()
            .map(|(evals, proofs)| {
                let evals_values: Vec<GoldilocksField> = evals
                    .iter()
                    .map(|f| GoldilocksField::from_canonical_u64(f.0))
                    .collect();
                let proofs_values = MerkleProofValues::from(proofs.clone());
                (evals_values, proofs_values)
            })
            .collect();
        FriInitialTreeProofValues { evals_proofs }
    }
}

#[derive(Clone, Debug, Default)]
pub struct FriQueryStepValues<F: PrimeField, const D: usize> {
    pub evals: Vec<ExtensionFieldValue<F, D>>,
    pub merkle_proof: MerkleProofValues<F>,
}

impl<F: PrimeField, const D: usize> FriQueryStepValues<F, D> {
    pub fn assign(
        config: &GoldilocksChipConfig<F>,
        ctx: &mut RegionCtx<'_, F>,
        fri_query_step_values: &Self,
    ) -> Result<AssignedFriQueryStepValues<F, D>, Error> {
        let evals = fri_query_step_values
            .evals
            .iter()
            .map(|v| ExtensionFieldValue::assign(config, ctx, v))
            .collect::<Result<Vec<AssignedExtensionFieldValue<F, D>>, Error>>()?;
        let merkle_proof = AssignedMerkleProofValues {
            siblings: fri_query_step_values
                .merkle_proof
                .siblings
                .iter()
                .map(|hash_value| HashValues::assign(config, ctx, hash_value))
                .collect::<Result<Vec<AssignedHashValues<F>>, Error>>()?,
        };
        Ok(AssignedFriQueryStepValues {
            evals,
            merkle_proof,
        })
    }
}

impl<F: PrimeField> From<FriQueryStep<GoldilocksField, Bn254PoseidonHash, 2>>
    for FriQueryStepValues<F, 2>
{
    fn from(value: FriQueryStep<GoldilocksField, Bn254PoseidonHash, 2>) -> Self {
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

#[derive(Clone, Debug, Default)]
pub struct FriQueryRoundValues<F: PrimeField, const D: usize> {
    pub initial_trees_proof: FriInitialTreeProofValues<F>,
    pub steps: Vec<FriQueryStepValues<F, D>>,
}

impl<F: PrimeField> From<FriQueryRound<GoldilocksField, Bn254PoseidonHash, 2>>
    for FriQueryRoundValues<F, 2>
{
    fn from(value: FriQueryRound<GoldilocksField, Bn254PoseidonHash, 2>) -> Self {
        Self {
            initial_trees_proof: FriInitialTreeProofValues::from(value.initial_trees_proof),
            steps: value
                .steps
                .iter()
                .map(|step| FriQueryStepValues::from(step.clone()))
                .collect_vec(),
        }
    }
}

impl<F: PrimeField, const D: usize> FriQueryRoundValues<F, D> {
    pub fn assign(
        config: &GoldilocksChipConfig<F>,
        ctx: &mut RegionCtx<'_, F>,
        fri_query_round_values: &Self,
    ) -> Result<AssignedFriQueryRoundValues<F, D>, Error> {
        let goldilocks_chip = GoldilocksChip::new(config);
        let evals = fri_query_round_values
            .initial_trees_proof
            .evals_proofs
            .iter()
            .map(|(values, _)| {
                values
                    .iter()
                    .map(|v| goldilocks_chip.assign_value(ctx, Value::known(goldilocks_to_fe(*v))))
                    .collect()
            })
            .collect::<Result<Vec<Vec<AssignedValue<F>>>, Error>>()?;

        let merkle_proofs = fri_query_round_values
            .initial_trees_proof
            .evals_proofs
            .iter()
            .map(|(_, merkle_proof_values)| {
                MerkleProofValues::assign(config, ctx, merkle_proof_values)
            })
            .collect::<Result<Vec<AssignedMerkleProofValues<F>>, Error>>()?;
        let evals_proofs = evals
            .into_iter()
            .zip_eq(merkle_proofs.into_iter())
            .collect_vec();
        let steps = fri_query_round_values
            .steps
            .iter()
            .map(|fri_query_step_values| {
                FriQueryStepValues::assign(config, ctx, fri_query_step_values)
            })
            .collect::<Result<Vec<AssignedFriQueryStepValues<F, D>>, Error>>()?;
        Ok(AssignedFriQueryRoundValues {
            initial_trees_proof: AssignedFriInitialTreeProofValues { evals_proofs },
            steps,
        })
    }
}

#[derive(Clone, Debug, Default)]
pub struct PolynomialCoeffsExtValues<F: PrimeField, const D: usize>(
    pub Vec<ExtensionFieldValue<F, D>>,
);

impl<F: PrimeField> From<PolynomialCoeffs<QuadraticExtension<GoldilocksField>>>
    for PolynomialCoeffsExtValues<F, 2>
{
    fn from(value: PolynomialCoeffs<QuadraticExtension<GoldilocksField>>) -> Self {
        Self(
            value
                .coeffs
                .iter()
                .map(|coeff| ExtensionFieldValue::from(coeff.0))
                .collect_vec(),
        )
    }
}

impl<F: PrimeField, const D: usize> PolynomialCoeffsExtValues<F, D> {
    pub fn assign(
        config: &GoldilocksChipConfig<F>,
        ctx: &mut RegionCtx<'_, F>,
        polynomial_coeffs_ext_values: &Self,
    ) -> Result<AssignedPolynomialCoeffsExtValues<F, D>, Error> {
        Ok(AssignedPolynomialCoeffsExtValues(
            polynomial_coeffs_ext_values
                .0
                .iter()
                .map(|v| ExtensionFieldValue::assign(config, ctx, v))
                .collect::<Result<Vec<AssignedExtensionFieldValue<F, D>>, Error>>()?,
        ))
    }
}

#[derive(Clone, Debug, Default)]
pub struct FriProofValues<F: PrimeField, const D: usize> {
    pub commit_phase_merkle_cap_values: Vec<MerkleCapValues<F>>,
    pub query_round_proofs: Vec<FriQueryRoundValues<F, D>>,
    pub final_poly: PolynomialCoeffsExtValues<F, D>,
    pub pow_witness: GoldilocksField,
}

impl<F: PrimeField> From<FriProof<GoldilocksField, Bn254PoseidonHash, 2>> for FriProofValues<F, 2> {
    fn from(value: FriProof<GoldilocksField, Bn254PoseidonHash, 2>) -> Self {
        Self {
            commit_phase_merkle_cap_values: value
                .commit_phase_merkle_caps
                .iter()
                .map(|cap| MerkleCapValues::from(cap.clone()))
                .collect_vec(),
            query_round_proofs: value
                .query_round_proofs
                .iter()
                .map(|proof| FriQueryRoundValues::from(proof.clone()))
                .collect_vec(),
            final_poly: PolynomialCoeffsExtValues::from(value.final_poly),
            pow_witness: to_goldilocks(value.pow_witness),
        }
    }
}

// check constant
impl<F: PrimeField, const D: usize> FriProofValues<F, D> {
    pub fn assign(
        config: &GoldilocksChipConfig<F>,
        ctx: &mut RegionCtx<'_, F>,
        fri_proof_values: &Self,
    ) -> Result<AssignedFriProofValues<F, D>, Error> {
        let commit_phase_merkle_cap_values = fri_proof_values
            .commit_phase_merkle_cap_values
            .iter()
            .map(|merkle_cap_values| MerkleCapValues::assign(config, ctx, merkle_cap_values))
            .collect::<Result<Vec<AssignedMerkleCapValues<F>>, Error>>()?;
        let query_round_proofs = fri_proof_values
            .query_round_proofs
            .iter()
            .map(|fri_query_round_values| {
                FriQueryRoundValues::assign(config, ctx, fri_query_round_values)
            })
            .collect::<Result<Vec<AssignedFriQueryRoundValues<F, D>>, Error>>()?;
        let final_poly =
            PolynomialCoeffsExtValues::assign(config, ctx, &fri_proof_values.final_poly)?;
        let goldilocks_chip = GoldilocksChip::new(config);
        let pow_witness = goldilocks_chip.assign_value(
            ctx,
            Value::known(goldilocks_to_fe(fri_proof_values.pow_witness)),
        )?;
        Ok(AssignedFriProofValues {
            commit_phase_merkle_cap_values,
            query_round_proofs,
            final_poly,
            pow_witness,
        })
    }
}

#[derive(Clone, Debug, Default)]
pub struct ProofValues<F: PrimeField, const D: usize> {
    pub wires_cap: MerkleCapValues<F>,
    pub plonk_zs_partial_products_cap: MerkleCapValues<F>,
    pub quotient_polys_cap: MerkleCapValues<F>,

    pub openings: OpeningSetValues<F, D>,
    pub opening_proof: FriProofValues<F, D>,
}

impl<F: PrimeField> From<Proof<GoldilocksField, Bn254PoseidonGoldilocksConfig, 2>>
    for ProofValues<F, 2>
{
    fn from(value: Proof<GoldilocksField, Bn254PoseidonGoldilocksConfig, 2>) -> Self {
        Self {
            wires_cap: MerkleCapValues::from(value.wires_cap),
            plonk_zs_partial_products_cap: MerkleCapValues::from(
                value.plonk_zs_partial_products_cap,
            ),
            quotient_polys_cap: MerkleCapValues::from(value.quotient_polys_cap),
            openings: OpeningSetValues::from(value.openings),
            opening_proof: FriProofValues::from(value.opening_proof),
        }
    }
}
