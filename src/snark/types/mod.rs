use std::marker::PhantomData;

use crate::snark::context::RegionCtx;
use halo2_proofs::circuit::Value;
use halo2_proofs::halo2curves::ff::PrimeField;
use halo2_proofs::plonk::Error;
use halo2wrong_maingate::AssignedValue;
use plonky2::field::extension::Extendable;
use plonky2::field::types::Field;
use plonky2::{
    field::goldilocks_field::GoldilocksField,
    hash::{hash_types::HashOut, merkle_tree::MerkleCap},
};

use self::assigned::{AssignedExtensionFieldValue, AssignedHashValues, AssignedMerkleCapValues};

use super::bn245_poseidon::plonky2_config::Bn254PoseidonHash;
use super::chip::goldilocks_chip::{GoldilocksChip, GoldilocksChipConfig};
use super::chip::native_chip::utils::goldilocks_to_fe;

pub mod assigned;
pub mod common_data;
pub mod fri;
pub mod proof;
pub mod verification_key;

pub fn to_goldilocks(e: GoldilocksField) -> GoldilocksField {
    GoldilocksField::from_canonical_u64(e.0)
}

#[derive(Clone, Debug, Default)]
pub struct HashValues<F: PrimeField> {
    pub elements: [GoldilocksField; 4],
    _marker: PhantomData<F>,
}

impl<F: PrimeField> HashValues<F> {
    pub fn assign(
        config: &GoldilocksChipConfig<F>,
        ctx: &mut RegionCtx<'_, F>,
        hash_value: &Self,
    ) -> Result<AssignedHashValues<F>, Error> {
        let goldilocks_chip = GoldilocksChip::new(config);
        let elements = hash_value
            .elements
            .iter()
            .map(|e| goldilocks_chip.assign_value(ctx, Value::known(goldilocks_to_fe(*e))))
            .collect::<Result<Vec<AssignedValue<F>>, Error>>()
            .unwrap()
            .try_into()
            .unwrap();
        Ok(AssignedHashValues { elements })
    }

    pub fn assign_constant(
        config: &GoldilocksChipConfig<F>,
        ctx: &mut RegionCtx<'_, F>,
        hash_value: &Self,
    ) -> Result<AssignedHashValues<F>, Error> {
        let goldilocks_chip = GoldilocksChip::new(config);
        let elements = hash_value
            .elements
            .iter()
            .map(|e| goldilocks_chip.assign_constant(ctx, *e))
            .collect::<Result<Vec<AssignedValue<F>>, Error>>()
            .unwrap()
            .try_into()
            .unwrap();
        Ok(AssignedHashValues { elements })
    }
}

impl<F: PrimeField> From<HashOut<GoldilocksField>> for HashValues<F> {
    fn from(value: HashOut<GoldilocksField>) -> Self {
        let mut elements = [GoldilocksField::ZERO; 4];
        for (to, from) in elements.iter_mut().zip(value.elements.iter()) {
            *to = to_goldilocks(*from);
        }
        HashValues {
            elements,
            _marker: PhantomData,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct MerkleCapValues<F: PrimeField>(pub Vec<HashValues<F>>);

impl<F: PrimeField> MerkleCapValues<F> {
    pub fn assign(
        config: &GoldilocksChipConfig<F>,
        ctx: &mut RegionCtx<'_, F>,
        merkle_cap_values: &Self,
    ) -> Result<AssignedMerkleCapValues<F>, Error> {
        let elements = merkle_cap_values
            .0
            .iter()
            .map(|hash_value| HashValues::assign(config, ctx, hash_value))
            .collect::<Result<Vec<AssignedHashValues<F>>, Error>>()?;
        Ok(AssignedMerkleCapValues(elements))
    }

    pub fn assign_constant(
        config: &GoldilocksChipConfig<F>,
        ctx: &mut RegionCtx<'_, F>,
        merkle_cap_values: &Self,
    ) -> Result<AssignedMerkleCapValues<F>, Error> {
        let elements = merkle_cap_values
            .0
            .iter()
            .map(|hash_value| HashValues::assign_constant(config, ctx, hash_value))
            .collect::<Result<Vec<AssignedHashValues<F>>, Error>>()?;
        Ok(AssignedMerkleCapValues(elements))
    }
}

impl<F: PrimeField> From<MerkleCap<GoldilocksField, Bn254PoseidonHash>> for MerkleCapValues<F> {
    fn from(value: MerkleCap<GoldilocksField, Bn254PoseidonHash>) -> Self {
        let cap_values = value.0.iter().map(|h| HashValues::from(*h)).collect();
        MerkleCapValues(cap_values)
    }
}

/// Contains a extension field value
#[derive(Clone, Debug)]
pub struct ExtensionFieldValue<F: PrimeField, const D: usize> {
    pub elements: [GoldilocksField; D],
    _marker: PhantomData<F>,
}

impl<F: PrimeField, const D: usize> Default for ExtensionFieldValue<F, D> {
    fn default() -> Self {
        Self {
            elements: [GoldilocksField::ZERO; D],
            _marker: PhantomData,
        }
    }
}

impl<F: PrimeField, const D: usize> ExtensionFieldValue<F, D> {
    pub fn assign(
        config: &GoldilocksChipConfig<F>,
        ctx: &mut RegionCtx<'_, F>,
        extension_field_value: &Self,
    ) -> Result<AssignedExtensionFieldValue<F, D>, Error> {
        let goldilocks_chip = GoldilocksChip::new(config);
        let elements = extension_field_value
            .elements
            .iter()
            .map(|v| goldilocks_chip.assign_value(ctx, Value::known(goldilocks_to_fe(*v))))
            .collect::<Result<Vec<AssignedValue<F>>, Error>>()?
            .try_into()
            .unwrap();
        Ok(AssignedExtensionFieldValue(elements))
    }
}

impl<F: PrimeField> From<[GoldilocksField; 2]> for ExtensionFieldValue<F, 2> {
    fn from(value: [GoldilocksField; 2]) -> Self {
        let mut elements = vec![];
        for from in value.iter() {
            elements.push(to_goldilocks(*from));
        }
        ExtensionFieldValue {
            elements: elements.try_into().unwrap(),
            _marker: PhantomData,
        }
    }
}

pub fn to_extension_field_values<F: PrimeField>(
    extension_fields: Vec<<GoldilocksField as Extendable<2>>::Extension>,
) -> Vec<ExtensionFieldValue<F, 2>> {
    extension_fields
        .iter()
        .map(|e| ExtensionFieldValue::from(e.0))
        .collect()
}
