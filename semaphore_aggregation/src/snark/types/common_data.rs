use std::ops::{Range, RangeFrom};

use crate::snark::{chip::plonk::gates::CustomGateRef, types::fri::FriOracleInfo};

use super::{fri::FriPolynomialInfo, to_goldilocks};
use halo2curves::{goldilocks::fp::Goldilocks, FieldExt};
use itertools::Itertools;
use plonky2::{field::goldilocks_field::GoldilocksField, plonk::circuit_data::CommonCircuitData, hash::hash_types::RichField};

#[derive(Clone, Debug, Default)]
pub struct FriConfig {
    /// `rate = 2^{-rate_bits}`.
    pub rate_bits: usize,

    /// Height of Merkle tree caps.
    pub cap_height: usize,

    pub proof_of_work_bits: u32,

    /// Number of query rounds to perform.
    pub num_query_rounds: usize,
}

#[derive(Clone, Debug, Default)]
pub struct CircuitConfig {
    pub num_wires: usize,
    pub num_routed_wires: usize,
    pub num_constants: usize,
    /// Whether to use a dedicated gate for base field arithmetic, rather than using a single gate
    /// for both base field and extension field arithmetic.
    pub use_base_arithmetic_gate: bool,
    pub security_bits: usize,
    /// The number of challenge points to generate, for IOPs that have soundness errors of (roughly)
    /// `degree / |F|`.
    pub num_challenges: usize,
    pub zero_knowledge: bool,
    /// A cap on the quotient polynomial's degree factor. The actual degree factor is derived
    /// systematically, but will never exceed this value.
    pub max_quotient_degree_factor: usize,
    pub fri_config: FriConfig,
}

#[derive(Clone, Debug, Default)]
pub struct FriParams {
    pub config: FriConfig,
    pub hiding: bool,
    pub degree_bits: usize,
    pub reduction_arity_bits: Vec<usize>,
}

impl FriParams {
    pub fn lde_bits(&self) -> usize {
        self.degree_bits + self.config.rate_bits
    }
}

#[derive(Clone, Default, Debug)]
pub struct SelectorsInfo {
    pub selector_indices: Vec<usize>,
    pub groups: Vec<Range<usize>>,
}

impl SelectorsInfo {
    pub fn num_selectors(&self) -> usize {
        self.groups.len()
    }
}

#[derive(Clone, Default)]
pub struct CommonData<F: FieldExt> {
    pub config: CircuitConfig,

    pub fri_params: FriParams,

    /// The types of gates used in this circuit, along with their prefixes.
    pub gates: Vec<CustomGateRef<F>>,

    /// Information on the circuit's selector polynomials.
    pub selectors_info: SelectorsInfo,

    /// The degree of the PLONK quotient polynomial.
    pub quotient_degree_factor: usize,

    /// The largest number of constraints imposed by any gate.
    pub num_gate_constraints: usize,

    /// The number of constant wires.
    pub num_constants: usize,

    pub num_public_inputs: usize,

    /// The `{k_i}` valued used in `S_ID_i` in Plonk's permutation argument.
    pub k_is: Vec<Goldilocks>,

    /// The number of partial products needed to compute the `Z` polynomials.
    pub num_partial_products: usize,
}

/// Holds the Merkle tree index and blinding flag of a set of polynomials used in FRI.
#[derive(Debug, Copy, Clone)]
pub struct PlonkOracle {
    pub(crate) index: usize,
    pub(crate) blinding: bool,
}

impl PlonkOracle {
    pub const CONSTANTS_SIGMAS: PlonkOracle = PlonkOracle {
        index: 0,
        blinding: false,
    };
    pub const WIRES: PlonkOracle = PlonkOracle {
        index: 1,
        blinding: true,
    };
    pub const ZS_PARTIAL_PRODUCTS: PlonkOracle = PlonkOracle {
        index: 2,
        blinding: true,
    };
    pub const QUOTIENT: PlonkOracle = PlonkOracle {
        index: 3,
        blinding: true,
    };
}

impl<F: FieldExt> CommonData<F> {
    pub const fn degree_bits(&self) -> usize {
        self.fri_params.degree_bits
    }

    pub fn degree(&self) -> usize {
        1 << self.degree_bits()
    }

    /// Range of the constants polynomials in the `constants_sigmas_commitment`.
    pub fn constants_range(&self) -> Range<usize> {
        0..self.num_constants
    }

    /// Range of the sigma polynomials in the `constants_sigmas_commitment`.
    pub fn sigmas_range(&self) -> Range<usize> {
        self.num_constants..self.num_constants + self.config.num_routed_wires
    }

    /// Range of the `z`s polynomials in the `zs_partial_products_commitment`.
    pub fn zs_range(&self) -> Range<usize> {
        0..self.config.num_challenges
    }

    /// Range of the partial products polynomials in the `zs_partial_products_commitment`.
    pub fn partial_products_range(&self) -> RangeFrom<usize> {
        self.config.num_challenges..
    }

    fn fri_preprocessed_polys(&self) -> Vec<FriPolynomialInfo> {
        FriPolynomialInfo::from_range(
            PlonkOracle::CONSTANTS_SIGMAS.index,
            0..self.num_preprocessed_polys(),
        )
    }

    fn num_preprocessed_polys(&self) -> usize {
        self.sigmas_range().end
    }

    fn fri_wire_polys(&self) -> Vec<FriPolynomialInfo> {
        let num_wire_polys = self.config.num_wires;
        FriPolynomialInfo::from_range(PlonkOracle::WIRES.index, 0..num_wire_polys)
    }

    fn num_zs_partial_products_polys(&self) -> usize {
        self.config.num_challenges * (1 + self.num_partial_products)
    }

    fn fri_zs_partial_products_polys(&self) -> Vec<FriPolynomialInfo> {
        FriPolynomialInfo::from_range(
            PlonkOracle::ZS_PARTIAL_PRODUCTS.index,
            0..self.num_zs_partial_products_polys(),
        )
    }

    pub fn fri_zs_polys(&self) -> Vec<FriPolynomialInfo> {
        FriPolynomialInfo::from_range(PlonkOracle::ZS_PARTIAL_PRODUCTS.index, self.zs_range())
    }

    pub(crate) fn num_quotient_polys(&self) -> usize {
        self.config.num_challenges * self.quotient_degree_factor
    }

    fn fri_quotient_polys(&self) -> Vec<FriPolynomialInfo> {
        FriPolynomialInfo::from_range(PlonkOracle::QUOTIENT.index, 0..self.num_quotient_polys())
    }

    pub fn fri_all_polys(&self) -> Vec<FriPolynomialInfo> {
        [
            self.fri_preprocessed_polys(),
            self.fri_wire_polys(),
            self.fri_zs_partial_products_polys(),
            self.fri_quotient_polys(),
        ]
        .concat()
    }

    pub fn fri_oracles(&self) -> Vec<FriOracleInfo> {
        vec![
            FriOracleInfo {
                num_polys: self.num_preprocessed_polys(),
                blinding: PlonkOracle::CONSTANTS_SIGMAS.blinding,
            },
            FriOracleInfo {
                num_polys: self.config.num_wires,
                blinding: PlonkOracle::WIRES.blinding,
            },
            FriOracleInfo {
                num_polys: self.num_zs_partial_products_polys(),
                blinding: PlonkOracle::ZS_PARTIAL_PRODUCTS.blinding,
            },
            FriOracleInfo {
                num_polys: self.num_quotient_polys(),
                blinding: PlonkOracle::QUOTIENT.blinding,
            },
        ]
    }
}

impl<F: FieldExt> From<CommonCircuitData<GoldilocksField, 2>> for CommonData<F> {
    fn from(value: CommonCircuitData<GoldilocksField, 2>) -> Self {
        Self {
            config: CircuitConfig {
                num_wires: value.config.num_wires,
                num_routed_wires: value.config.num_routed_wires,
                num_constants: value.config.num_constants,
                use_base_arithmetic_gate: value.config.use_base_arithmetic_gate,
                security_bits: value.config.security_bits,
                num_challenges: value.config.num_challenges,
                zero_knowledge: value.config.zero_knowledge,
                max_quotient_degree_factor: value.config.max_quotient_degree_factor,
                fri_config: FriConfig {
                    rate_bits: value.config.fri_config.rate_bits,
                    cap_height: value.config.fri_config.cap_height,
                    proof_of_work_bits: value.config.fri_config.proof_of_work_bits,
                    num_query_rounds: value.config.fri_config.num_query_rounds,
                },
            },
            gates: value
                .gates
                .iter()
                .map(|gate| CustomGateRef::from(gate))
                .collect(),
            fri_params: FriParams {
                config: FriConfig {
                    rate_bits: value.config.fri_config.rate_bits,
                    cap_height: value.config.fri_config.cap_height,
                    proof_of_work_bits: value.config.fri_config.proof_of_work_bits,
                    num_query_rounds: value.config.fri_config.num_query_rounds,
                },
                hiding: value.fri_params.hiding,
                degree_bits: value.fri_params.degree_bits,
                reduction_arity_bits: value.fri_params.reduction_arity_bits,
            },
            selectors_info: SelectorsInfo {
                selector_indices: value.selectors_info.selector_indices,
                groups: value.selectors_info.groups,
            },
            quotient_degree_factor: value.quotient_degree_factor,
            num_gate_constraints: value.num_gate_constraints,
            num_constants: value.num_constants,
            num_public_inputs: value.num_public_inputs,
            k_is: value.k_is.iter().map(|e| to_goldilocks(*e)).collect(),
            num_partial_products: value.num_partial_products,
        }
    }
}
