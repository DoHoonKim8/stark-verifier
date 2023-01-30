/// This module contains Plonky2 types encoded into halo2 circuit.
use halo2curves::FieldExt;
use halo2_proofs::circuit::Value;

#[derive(Debug)]
pub struct MerkleCapValues<F: FieldExt>(pub Vec<[Value<F>; 4]>);

/// Contains assigned values that represent extension field value
#[derive(Debug)]
pub struct ExtensionFieldValues<F: FieldExt, const D: usize>(pub [Value<F>; D]);

#[derive(Debug)]
pub struct OpeningSetValues<F: FieldExt, const D: usize> {
    pub constants: Vec<ExtensionFieldValues<F, D>>,
    pub plonk_sigmas: Vec<ExtensionFieldValues<F, D>>,
    pub wires: Vec<ExtensionFieldValues<F, D>>,
    pub plonk_zs: Vec<ExtensionFieldValues<F, D>>,
    pub plonk_zs_next: Vec<ExtensionFieldValues<F, D>>,
    pub partial_products: Vec<ExtensionFieldValues<F, D>>,
    pub quotient_polys: Vec<ExtensionFieldValues<F, D>>,
}

#[derive(Debug)]
pub struct MerkleProofValues<F: FieldExt> {
    pub siblings: Vec<[Value<F>; 4]>,
}

#[derive(Debug)]
pub struct FriInitialTreeProofValues<F: FieldExt> {
    pub evals_proofs: Vec<(Vec<Value<F>>, MerkleProofValues<F>)>,
}

#[derive(Debug)]
pub struct FriQueryStepValues<F: FieldExt, const D: usize> {
    pub evals: Vec<ExtensionFieldValues<F, D>>,
    pub merkle_proof: MerkleProofValues<F>,
}

#[derive(Debug)]
pub struct FriQueryRoundValues<F: FieldExt, const D: usize> {
    pub initial_trees_proof: FriInitialTreeProofValues<F>,
    pub steps: Vec<FriQueryStepValues<F, D>>,
}

#[derive(Debug)]
pub struct PolynomialCoeffsExtValues<F: FieldExt, const D: usize>(pub Vec<ExtensionFieldValues<F, D>>);

#[derive(Debug)]
pub struct FriProofValues<F: FieldExt, const D: usize> {
    pub commit_phase_merkle_values: Vec<MerkleCapValues<F>>,
    pub query_round_proofs: Vec<FriQueryRoundValues<F, D>>,
    pub final_poly: PolynomialCoeffsExtValues<F, D>,
    pub pow_witness: Value<F>,
}

#[derive(Debug)]
pub struct ProofValues<F: FieldExt, const D: usize> {
    pub wires_cap: MerkleCapValues<F>,
    pub plonk_zs_partial_products_cap: MerkleCapValues<F>,
    pub quotient_polys_cap: MerkleCapValues<F>,

    pub openings: OpeningSetValues<F, D>,
    pub opening_proof: FriProofValues<F, D>,
}
