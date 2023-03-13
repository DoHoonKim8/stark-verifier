use std::ops::Range;

use crate::snark::chip::plonk::gates::CustomGateRef;

use super::to_goldilocks;
use halo2curves::goldilocks::fp::Goldilocks;
use plonky2::{field::goldilocks_field::GoldilocksField, plonk::circuit_data::CommonCircuitData};

#[derive(Debug, Default)]
pub struct FriConfig {
    /// `rate = 2^{-rate_bits}`.
    pub rate_bits: usize,

    /// Height of Merkle tree caps.
    pub cap_height: usize,

    pub proof_of_work_bits: u32,

    /// Number of query rounds to perform.
    pub num_query_rounds: usize,
}

#[derive(Debug, Default)]
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

#[derive(Debug, Default)]
pub struct FriParams {
    pub hiding: bool,
    pub degree_bits: usize,
    pub reduction_arity_bits: Vec<usize>,
}

#[derive(Default, Debug)]
pub struct SelectorsInfo {
    pub selector_indices: Vec<usize>,
    pub groups: Vec<Range<usize>>,
}

impl SelectorsInfo {
    pub fn num_selectors(&self) -> usize {
        self.groups.len()
    }
}

#[derive(Default)]
pub struct CommonData {
    pub config: CircuitConfig,

    pub fri_params: FriParams,

    /// The types of gates used in this circuit, along with their prefixes.
    pub gates: Vec<CustomGateRef>,

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

impl CommonData {
    pub const fn degree_bits(&self) -> usize {
        self.fri_params.degree_bits
    }

    pub fn degree(&self) -> usize {
        1 << self.degree_bits()
    }
}

impl From<CommonCircuitData<GoldilocksField, 2>> for CommonData {
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
