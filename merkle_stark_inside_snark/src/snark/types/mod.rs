use halo2_proofs::circuit::Value;
use halo2curves::{goldilocks::fp::Goldilocks, FieldExt};
use plonky2::field::extension::Extendable;
use plonky2::{
    field::goldilocks_field::GoldilocksField,
    hash::{hash_types::HashOut, merkle_tree::MerkleCap, poseidon::PoseidonHash},
};

pub mod assigned;
pub mod common_data;
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
