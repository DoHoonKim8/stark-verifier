use core::ops::Range;
use halo2_proofs::circuit::Value;
use halo2curves::{goldilocks::fp::Goldilocks, FieldExt};
use plonky2::field::extension::Extendable;
use plonky2::plonk::circuit_data::CommonCircuitData;
use plonky2::{
    field::goldilocks_field::GoldilocksField,
    hash::{hash_types::HashOut, merkle_tree::MerkleCap, poseidon::PoseidonHash},
};

pub mod assigned;
pub mod proof;
pub mod verification_key;

pub fn to_goldilocks(e: GoldilocksField) -> Goldilocks {
    Goldilocks::from(e.0)
}

#[derive(Debug, Default)]
pub struct HashValues<F: FieldExt> {
    pub elements: [Value<F>; 4],
}

impl From<HashOut<GoldilocksField>> for HashValues<Goldilocks> {
    fn from(value: HashOut<GoldilocksField>) -> Self {
        let mut elements = [Value::unknown(); 4];
        for (to, from) in elements.iter_mut().zip(value.elements.iter()) {
            *to = Value::known(Goldilocks::from(from.0));
        }
        HashValues { elements }
    }
}

#[derive(Debug, Default)]
pub struct MerkleCapValues<F: FieldExt>(pub Vec<HashValues<F>>);

impl From<MerkleCap<GoldilocksField, PoseidonHash>> for MerkleCapValues<Goldilocks> {
    fn from(value: MerkleCap<GoldilocksField, PoseidonHash>) -> Self {
        let cap_values = value.0.iter().map(|h| HashValues::from(*h)).collect();
        MerkleCapValues(cap_values)
    }
}

/// Contains a extension field value
#[derive(Debug)]
pub struct ExtensionFieldValue<F: FieldExt, const D: usize>(pub [Value<F>; D]);

impl<F: FieldExt, const D: usize> Default for ExtensionFieldValue<F, D> {
    fn default() -> Self {
        Self([Value::unknown(); D])
    }
}

// impl From<<GoldilocksField as Extendable<2>>::Extension> for ExtensionFieldValue<Goldilocks, 2> {

// }

impl<const D: usize> From<[GoldilocksField; D]> for ExtensionFieldValue<Goldilocks, D> {
    fn from(value: [GoldilocksField; D]) -> Self {
        let mut elements = [Value::unknown(); D];
        for (to, from) in elements.iter_mut().zip(value.iter()) {
            *to = Value::known(to_goldilocks(*from));
        }
        ExtensionFieldValue(elements)
    }
}

pub fn to_extension_field_values(
    extension_fields: Vec<<GoldilocksField as Extendable<2>>::Extension>,
) -> Vec<ExtensionFieldValue<Goldilocks, 2>> {
    extension_fields
        .iter()
        .map(|e| ExtensionFieldValue::from(e.0))
        .collect()
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

#[derive(Debug, Default)]
pub struct CommonData<F: FieldExt> {
    pub config: CircuitConfig,

    pub fri_params: FriParams,

    /// The types of gates used in this circuit, along with their prefixes.
    /// pub(crate) gates: Vec<GateRef<F, D>>,

    /// Information on the circuit's selector polynomials.
    /// pub selectors_info: SelectorsInfo,

    /// The degree of the PLONK quotient polynomial.
    pub quotient_degree_factor: usize,

    /// The largest number of constraints imposed by any gate.
    pub num_gate_constraints: usize,

    /// The number of constant wires.
    pub num_constants: usize,

    pub num_public_inputs: usize,

    /// The `{k_i}` valued used in `S_ID_i` in Plonk's permutation argument.
    pub k_is: Vec<F>,

    /// The number of partial products needed to compute the `Z` polynomials.
    pub num_partial_products: usize,
}

impl From<CommonCircuitData<GoldilocksField, 2>> for CommonData<Goldilocks> {
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
            },
            fri_params: FriParams {
                hiding: value.fri_params.hiding,
                degree_bits: value.fri_params.degree_bits,
                reduction_arity_bits: value.fri_params.reduction_arity_bits,
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
