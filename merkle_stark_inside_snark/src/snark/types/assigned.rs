use halo2curves::FieldExt;
use halo2wrong_maingate::AssignedValue;

#[derive(Clone)]
pub struct AssignedHashValues<F: FieldExt> {
    pub elements: [AssignedValue<F>; 4],
}

#[derive(Clone)]
pub struct AssignedMerkleCapValues<F: FieldExt>(pub Vec<AssignedHashValues<F>>);

#[derive(Clone)]
pub struct AssignedExtensionFieldValue<F: FieldExt, const D: usize>(pub [AssignedValue<F>; D]);

pub struct AssignedOpeningSetValues<F: FieldExt, const D: usize> {
    pub constants: Vec<AssignedExtensionFieldValue<F, D>>,
    pub plonk_sigmas: Vec<AssignedExtensionFieldValue<F, D>>,
    pub wires: Vec<AssignedExtensionFieldValue<F, D>>,
    pub plonk_zs: Vec<AssignedExtensionFieldValue<F, D>>,
    pub plonk_zs_next: Vec<AssignedExtensionFieldValue<F, D>>,
    pub partial_products: Vec<AssignedExtensionFieldValue<F, D>>,
    pub quotient_polys: Vec<AssignedExtensionFieldValue<F, D>>,
}

pub struct AssignedMerkleProofValues<F: FieldExt> {
    pub siblings: Vec<AssignedHashValues<F>>,
}

pub struct AssignedFriInitialTreeProofValues<F: FieldExt> {
    pub evals_proofs: Vec<(Vec<AssignedValue<F>>, AssignedMerkleProofValues<F>)>,
}

pub struct AssignedFriQueryStepValues<F: FieldExt, const D: usize> {
    pub evals: Vec<AssignedExtensionFieldValue<F, D>>,
    pub merkle_proof: AssignedMerkleProofValues<F>,
}

pub struct AssignedFriQueryRoundValues<F: FieldExt, const D: usize> {
    pub initial_trees_proof: AssignedFriInitialTreeProofValues<F>,
    pub steps: Vec<AssignedFriQueryStepValues<F, D>>,
}

pub struct AssignedPolynomialCoeffsExtValues<F: FieldExt, const D: usize>(
    pub Vec<AssignedExtensionFieldValue<F, D>>,
);

pub struct AssignedFriProofValues<F: FieldExt, const D: usize> {
    pub commit_phase_merkle_cap_values: Vec<AssignedMerkleCapValues<F>>,
    pub query_round_proofs: Vec<AssignedFriQueryRoundValues<F, D>>,
    pub final_poly: AssignedPolynomialCoeffsExtValues<F, D>,
    pub pow_witness: AssignedValue<F>,
}

pub struct AssignedProofValues<F: FieldExt, const D: usize> {
    pub wires_cap: AssignedMerkleCapValues<F>,
    pub plonk_zs_partial_products_cap: AssignedMerkleCapValues<F>,
    pub quotient_polys_cap: AssignedMerkleCapValues<F>,

    pub openings: AssignedOpeningSetValues<F, D>,
    pub opening_proof: AssignedFriProofValues<F, D>,
}

pub struct AssignedProofWithPisValues<F: FieldExt, const D: usize> {
    pub proof: AssignedProofValues<F, D>,
    pub public_inputs: Vec<AssignedValue<F>>,
}

pub struct AssignedVerificationKeyValues<F: FieldExt> {
    pub constants_sigmas_cap: AssignedMerkleCapValues<F>,
    pub circuit_digest: AssignedHashValues<F>,
}

pub struct AssignedFriChallenges<F: FieldExt, const D: usize> {
    pub fri_alpha: AssignedExtensionFieldValue<F, D>,
    pub fri_betas: Vec<AssignedExtensionFieldValue<F, D>>,
    pub fri_pow_response: AssignedValue<F>,
    pub fri_query_indices: Vec<AssignedValue<F>>,
}

/// Opened values of each polynomial.
pub struct AssignedFriOpenings<F: FieldExt, const D: usize> {
    pub batches: Vec<AssignedFriOpeningBatch<F, D>>,
}

/// Opened values of each polynomial that's opened at a particular point.
pub struct AssignedFriOpeningBatch<F: FieldExt, const D: usize> {
    pub values: Vec<AssignedExtensionFieldValue<F, D>>,
}

pub struct AssignedProofChallenges<F: FieldExt, const D: usize> {
    pub plonk_betas: Vec<AssignedValue<F>>,
    pub plonk_gammas: Vec<AssignedValue<F>>,
    pub plonk_alphas: Vec<AssignedValue<F>>,
    pub plonk_zeta: AssignedExtensionFieldValue<F, D>,
    pub fri_challenges: AssignedFriChallenges<F, D>,
}
