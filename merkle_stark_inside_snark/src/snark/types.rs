use core::ops::Range;
use halo2_proofs::circuit::Value;
use halo2curves::{goldilocks::fp::Goldilocks, FieldExt};
use plonky2::{
    field::{extension::Extendable, goldilocks_field::GoldilocksField},
    fri::proof::FriInitialTreeProof,
    hash::{
        hash_types::HashOut, merkle_proofs::MerkleProof, merkle_tree::MerkleCap,
        poseidon::PoseidonHash,
    },
};

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

impl<const D: usize> From<Vec<GoldilocksField>> for ExtensionFieldValue<Goldilocks, D> {
    fn from(value: Vec<GoldilocksField>) -> Self {
        let mut elements = [Value::unknown(); D];
        for (to, from) in elements.iter_mut().zip(value.iter()) {
            *to = Value::known(to_goldilocks(*from));
        }
        ExtensionFieldValue(elements)
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
    pub siblings: Vec<HashValues<F>>,
}

impl From<MerkleProof<GoldilocksField, PoseidonHash>> for MerkleProofValues<Goldilocks> {
    fn from(value: MerkleProof<GoldilocksField, PoseidonHash>) -> Self {
        let siblings = value
            .siblings
            .iter()
            .map(|value| HashValues::from(*value))
            .collect();
        MerkleProofValues { siblings }
    }
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

#[derive(Debug, Default)]
pub struct VerificationKeyValues<F: FieldExt> {
    pub constants_sigmas_cap: MerkleCapValues<F>,
    pub circuit_digest: HashValues<F>,
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
pub struct CommonValues<F: FieldExt> {
    pub config: CircuitConfig,

    pub fri_params: FriParams,

    /// The types of gates used in this circuit, along with their prefixes.
    /// pub(crate) gates: Vec<GateRef<F, D>>,

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
    pub k_is: Vec<F>,

    /// The number of partial products needed to compute the `Z` polynomials.
    pub num_partial_products: usize,
}
