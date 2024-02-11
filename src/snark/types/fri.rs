use std::ops::Range;

use halo2_proofs::halo2curves::ff::PrimeField;

use super::{assigned::AssignedExtensionFieldValue, common_data::CommonData};

#[derive(Copy, Clone)]
pub struct FriOracleInfo {
    pub num_polys: usize,
    pub blinding: bool,
}

#[derive(Copy, Clone, Debug)]
pub struct FriPolynomialInfo {
    /// Index into `FriInstanceInfo`'s `oracles` list.
    pub oracle_index: usize,
    /// Index of the polynomial within the oracle.
    pub polynomial_index: usize,
}

impl FriPolynomialInfo {
    pub fn from_range(
        oracle_index: usize,
        polynomial_indices: Range<usize>,
    ) -> Vec<FriPolynomialInfo> {
        polynomial_indices
            .map(|polynomial_index| FriPolynomialInfo {
                oracle_index,
                polynomial_index,
            })
            .collect()
    }
}

/// A batch of openings at a particular point.
pub struct FriBatchInfo<F: PrimeField, const D: usize> {
    pub point: AssignedExtensionFieldValue<F, D>,
    pub polynomials: Vec<FriPolynomialInfo>,
}

/// Describes an instance of a FRI-based batch opening.
pub struct FriInstanceInfo<F: PrimeField, const D: usize> {
    /// The oracles involved, not counting oracles created during the commit phase.
    pub oracles: Vec<FriOracleInfo>,
    /// Batches of openings, where each batch is associated with a particular point.
    pub batches: Vec<FriBatchInfo<F, D>>,
}

impl<F: PrimeField, const D: usize> FriInstanceInfo<F, D> {
    pub fn new(
        zeta: &AssignedExtensionFieldValue<F, D>,
        zeta_next: &AssignedExtensionFieldValue<F, D>,
        common_data: &CommonData<F>,
    ) -> Self {
        // All polynomials are opened at zeta.
        let zeta_batch = FriBatchInfo {
            point: zeta.clone(),
            polynomials: common_data.fri_all_polys(),
        };

        // The Z polynomials are also opened at g * zeta.
        let zeta_next_batch = FriBatchInfo {
            point: zeta_next.clone(),
            polynomials: common_data.fri_zs_polys(),
        };

        let openings = vec![zeta_batch, zeta_next_batch];
        FriInstanceInfo {
            oracles: common_data.fri_oracles(),
            batches: openings,
        }
    }
}
