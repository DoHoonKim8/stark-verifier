use super::{ExtensionFieldValue, MerkleCapValues, MerkleProofValues};
use halo2_proofs::circuit::Value;
use halo2curves::{goldilocks::fp::Goldilocks, FieldExt};
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

#[derive(Debug, Default)]
pub struct PolynomialCoeffsExtValues<F: FieldExt, const D: usize>(
    pub Vec<ExtensionFieldValue<F, D>>,
);

#[derive(Debug, Default)]
pub struct FriProofValues<F: FieldExt, const D: usize> {
    pub commit_phase_merkle_values: Vec<MerkleCapValues<F>>,
    pub query_round_proofs: Vec<FriQueryRoundValues<F, D>>,
    pub final_poly: PolynomialCoeffsExtValues<F, D>,
    pub pow_witness: Value<F>,
}

#[derive(Debug, Default)]
pub struct ProofValues<F: FieldExt, const D: usize> {
    pub wires_cap: MerkleCapValues<F>,
    pub plonk_zs_partial_products_cap: MerkleCapValues<F>,
    pub quotient_polys_cap: MerkleCapValues<F>,

    pub openings: OpeningSetValues<F, D>,
    pub opening_proof: FriProofValues<F, D>,
}
