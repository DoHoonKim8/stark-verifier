use halo2_proofs::halo2curves::ff::PrimeField;
use halo2wrong_maingate::AssignedValue;

#[derive(Clone)]
pub struct AssignedHashValues<F: PrimeField> {
    pub elements: [AssignedValue<F>; 4],
}

#[derive(Clone)]
pub struct AssignedMerkleCapValues<F: PrimeField>(pub Vec<AssignedHashValues<F>>);

#[derive(Clone, Debug)]
pub struct AssignedExtensionFieldValue<F: PrimeField, const D: usize>(pub [AssignedValue<F>; D]);

pub struct AssignedOpeningSetValues<F: PrimeField, const D: usize> {
    pub constants: Vec<AssignedExtensionFieldValue<F, D>>,
    pub plonk_sigmas: Vec<AssignedExtensionFieldValue<F, D>>,
    pub wires: Vec<AssignedExtensionFieldValue<F, D>>,
    pub plonk_zs: Vec<AssignedExtensionFieldValue<F, D>>,
    pub plonk_zs_next: Vec<AssignedExtensionFieldValue<F, D>>,
    pub partial_products: Vec<AssignedExtensionFieldValue<F, D>>,
    pub quotient_polys: Vec<AssignedExtensionFieldValue<F, D>>,
}

impl<F: PrimeField, const D: usize> AssignedOpeningSetValues<F, D> {
    pub(crate) fn to_fri_openings(&self) -> AssignedFriOpenings<F, D> {
        let zeta_batch = AssignedFriOpeningBatch {
            values: [
                self.constants.as_slice(),
                self.plonk_sigmas.as_slice(),
                self.wires.as_slice(),
                self.plonk_zs.as_slice(),
                self.partial_products.as_slice(),
                self.quotient_polys.as_slice(),
            ]
            .concat(),
        };
        let zeta_next_batch = AssignedFriOpeningBatch {
            values: self.plonk_zs_next.clone(),
        };
        AssignedFriOpenings {
            batches: vec![zeta_batch, zeta_next_batch],
        }
    }
}

#[derive(Clone)]
pub struct AssignedMerkleProofValues<F: PrimeField> {
    pub siblings: Vec<AssignedHashValues<F>>,
}

#[derive(Clone)]
pub struct AssignedFriInitialTreeProofValues<F: PrimeField> {
    pub evals_proofs: Vec<(Vec<AssignedValue<F>>, AssignedMerkleProofValues<F>)>,
}

impl<F: PrimeField> AssignedFriInitialTreeProofValues<F> {
    pub(crate) fn unsalted_eval(
        &self,
        oracle_index: usize,
        poly_index: usize,
        salted: bool,
    ) -> AssignedValue<F> {
        self.unsalted_evals(oracle_index, salted)[poly_index].clone()
    }

    fn unsalted_evals(&self, oracle_index: usize, salted: bool) -> &[AssignedValue<F>] {
        let evals = &self.evals_proofs[oracle_index].0;
        let salt_size = if salted { 4 } else { 0 };
        &evals[..evals.len() - salt_size]
    }
}

#[derive(Clone)]
pub struct AssignedFriQueryStepValues<F: PrimeField, const D: usize> {
    pub evals: Vec<AssignedExtensionFieldValue<F, D>>,
    pub merkle_proof: AssignedMerkleProofValues<F>,
}

#[derive(Clone)]
pub struct AssignedFriQueryRoundValues<F: PrimeField, const D: usize> {
    pub initial_trees_proof: AssignedFriInitialTreeProofValues<F>,
    pub steps: Vec<AssignedFriQueryStepValues<F, D>>,
}

#[derive(Clone)]
pub struct AssignedPolynomialCoeffsExtValues<F: PrimeField, const D: usize>(
    pub Vec<AssignedExtensionFieldValue<F, D>>,
);

#[derive(Clone)]
pub struct AssignedFriProofValues<F: PrimeField, const D: usize> {
    pub commit_phase_merkle_cap_values: Vec<AssignedMerkleCapValues<F>>,
    pub query_round_proofs: Vec<AssignedFriQueryRoundValues<F, D>>,
    pub final_poly: AssignedPolynomialCoeffsExtValues<F, D>,
    pub pow_witness: AssignedValue<F>,
}

pub struct AssignedProofValues<F: PrimeField, const D: usize> {
    pub wires_cap: AssignedMerkleCapValues<F>,
    pub plonk_zs_partial_products_cap: AssignedMerkleCapValues<F>,
    pub quotient_polys_cap: AssignedMerkleCapValues<F>,

    pub openings: AssignedOpeningSetValues<F, D>,
    pub opening_proof: AssignedFriProofValues<F, D>,
}

pub struct AssignedProofWithPisValues<F: PrimeField, const D: usize> {
    pub proof: AssignedProofValues<F, D>,
    pub public_inputs: Vec<AssignedValue<F>>,
}

pub struct AssignedVerificationKeyValues<F: PrimeField> {
    pub constants_sigmas_cap: AssignedMerkleCapValues<F>,
    pub circuit_digest: AssignedHashValues<F>,
}

#[derive(Clone)]
pub struct AssignedFriChallenges<F: PrimeField, const D: usize> {
    pub fri_alpha: AssignedExtensionFieldValue<F, D>,
    pub fri_betas: Vec<AssignedExtensionFieldValue<F, D>>,
    pub fri_pow_response: AssignedValue<F>,
    pub fri_query_indices: Vec<AssignedValue<F>>,
}

/// Opened values of each polynomial.
pub struct AssignedFriOpenings<F: PrimeField, const D: usize> {
    pub batches: Vec<AssignedFriOpeningBatch<F, D>>,
}

/// Opened values of each polynomial that's opened at a particular point.
pub struct AssignedFriOpeningBatch<F: PrimeField, const D: usize> {
    pub values: Vec<AssignedExtensionFieldValue<F, D>>,
}

pub struct AssignedProofChallenges<F: PrimeField, const D: usize> {
    pub plonk_betas: Vec<AssignedValue<F>>,
    pub plonk_gammas: Vec<AssignedValue<F>>,
    pub plonk_alphas: Vec<AssignedValue<F>>,
    pub plonk_zeta: AssignedExtensionFieldValue<F, D>,
    pub fri_challenges: AssignedFriChallenges<F, D>,
}
