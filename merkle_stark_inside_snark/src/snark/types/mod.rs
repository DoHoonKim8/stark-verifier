use halo2_proofs::circuit::Value;
use halo2_proofs::plonk::Error;
use halo2curves::{goldilocks::fp::Goldilocks, FieldExt};
use halo2wrong::RegionCtx;
use halo2wrong_maingate::{AssignedValue, MainGateInstructions};
use plonky2::field::extension::Extendable;
use plonky2::{
    field::goldilocks_field::GoldilocksField,
    hash::{hash_types::HashOut, merkle_tree::MerkleCap, poseidon::PoseidonHash},
};

use self::assigned::{AssignedExtensionFieldValue, AssignedHashValues, AssignedMerkleCapValues};

use crate::snark::chip::plonk::plonk_verifier_chip::PlonkVerifierChip;

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

impl HashValues<Goldilocks> {
    pub fn assign(
        verifier: &PlonkVerifierChip,
        ctx: &mut RegionCtx<'_, Goldilocks>,
        hash_value: &Self,
    ) -> Result<AssignedHashValues<Goldilocks>, Error> {
        let main_gate = verifier.main_gate();
        let elements = hash_value
            .elements
            .iter()
            .map(|e| main_gate.assign_value(ctx, *e))
            .collect::<Result<Vec<AssignedValue<Goldilocks>>, Error>>()
            .unwrap()
            .try_into()
            .unwrap();
        Ok(AssignedHashValues { elements })
    }
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

impl MerkleCapValues<Goldilocks> {
    pub fn assign(
        verifier: &PlonkVerifierChip,
        ctx: &mut RegionCtx<'_, Goldilocks>,
        merkle_cap_values: &Self,
    ) -> Result<AssignedMerkleCapValues<Goldilocks>, Error> {
        let elements = merkle_cap_values
            .0
            .iter()
            .map(|hash_value| HashValues::assign(verifier, ctx, hash_value))
            .collect::<Result<Vec<AssignedHashValues<Goldilocks>>, Error>>()?;
        Ok(AssignedMerkleCapValues(elements))
    }
}

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

impl ExtensionFieldValue<Goldilocks, 2> {
    pub fn assign(
        verifier: &PlonkVerifierChip,
        ctx: &mut RegionCtx<'_, Goldilocks>,
        extension_field_value: &Self,
    ) -> Result<AssignedExtensionFieldValue<Goldilocks, 2>, Error> {
        let main_gate = verifier.main_gate();
        let elements = extension_field_value
            .0
            .iter()
            .map(|v| main_gate.assign_value(ctx, *v))
            .collect::<Result<Vec<AssignedValue<Goldilocks>>, Error>>()?
            .try_into()
            .unwrap();
        Ok(AssignedExtensionFieldValue(elements))
    }
}

// impl From<<GoldilocksField as Extendable<2>>::Extension> for ExtensionFieldValue<Goldilocks, 2> {

// }

impl From<[GoldilocksField; 2]> for ExtensionFieldValue<Goldilocks, 2> {
    fn from(value: [GoldilocksField; 2]) -> Self {
        let mut elements = [Value::unknown(); 2];
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
