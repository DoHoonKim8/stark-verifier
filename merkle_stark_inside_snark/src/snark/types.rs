/// This module contains Plonky2 types encoded into halo2 circuit.
use halo2_proofs::circuit::Value;
use halo2curves::FieldExt;

#[derive(Debug, Default)]
pub struct HashValues<F: FieldExt> {
    pub elements: [Value<F>; 4],
}

#[derive(Debug, Default)]
pub struct MerkleCapValues<F: FieldExt>(pub Vec<HashValues<F>>);

/// Contains a extension field value
#[derive(Debug)]
pub struct ExtensionFieldValue<F: FieldExt, const D: usize>(pub [Value<F>; D]);

impl<F: FieldExt, const D: usize> Default for ExtensionFieldValue<F, D> {
    fn default() -> Self {
        Self([Value::unknown(); D])
    }
}

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
pub struct MerkleProofValues<F: FieldExt> {
    pub siblings: Vec<[Value<F>; 4]>,
}

#[derive(Debug, Default)]
pub struct FriInitialTreeProofValues<F: FieldExt> {
    pub evals_proofs: Vec<(Vec<Value<F>>, MerkleProofValues<F>)>,
}

#[derive(Debug, Default)]
pub struct FriQueryStepValues<F: FieldExt, const D: usize> {
    pub evals: Vec<ExtensionFieldValue<F, D>>,
    pub merkle_proof: MerkleProofValues<F>,
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
