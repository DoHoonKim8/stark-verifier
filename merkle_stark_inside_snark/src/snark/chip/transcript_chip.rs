use crate::snark::{
    chip::hasher_chip::HasherChip,
    types::assigned::{AssignedExtensionFieldValue, AssignedHashValues, AssignedMerkleCapValues},
};
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::plonk::Error;
use halo2curves::goldilocks::fp::Goldilocks;
use halo2wrong::RegionCtx;
use halo2wrong_maingate::AssignedValue;
use poseidon::Spec;

use super::goldilocks_chip::GoldilocksChipConfig;

pub struct TranscriptChip<N: FieldExt, const T: usize, const T_MINUS_ONE: usize, const RATE: usize>
{
    hasher_chip: HasherChip<N, T, T_MINUS_ONE, RATE>,
}

impl<N: FieldExt, const T: usize, const T_MINUS_ONE: usize, const RATE: usize>
    TranscriptChip<N, T, T_MINUS_ONE, RATE>
{
    /// Constructs the transcript chip
    pub fn new(
        ctx: &mut RegionCtx<'_, N>,
        spec: &Spec<Goldilocks, T, T_MINUS_ONE>,
        goldilocks_chip_config: &GoldilocksChipConfig<N>,
    ) -> Result<Self, Error> {
        let hasher_chip = HasherChip::new(ctx, spec, goldilocks_chip_config)?;
        Ok(Self { hasher_chip })
    }

    /// Write scalar to the transcript
    pub fn write_scalar(
        &mut self,
        ctx: &mut RegionCtx<'_, N>,
        scalar: &AssignedValue<N>,
    ) -> Result<(), Error> {
        self.hasher_chip.update(ctx, scalar)
    }

    pub fn write_extension<const D: usize>(
        &mut self,
        ctx: &mut RegionCtx<'_, N>,
        extension: &AssignedExtensionFieldValue<N, D>,
    ) -> Result<(), Error> {
        for scalar in extension.0.iter() {
            self.write_scalar(ctx, scalar)?;
        }
        Ok(())
    }

    pub fn write_hash(
        &mut self,
        ctx: &mut RegionCtx<'_, N>,
        hash: &AssignedHashValues<N>,
    ) -> Result<(), Error> {
        for scalar in hash.elements.iter() {
            self.write_scalar(ctx, scalar)?;
        }
        Ok(())
    }

    pub fn write_cap(
        &mut self,
        ctx: &mut RegionCtx<'_, N>,
        cap: &AssignedMerkleCapValues<N>,
    ) -> Result<(), Error> {
        for hash in cap.0.iter() {
            self.write_hash(ctx, &hash)?;
        }
        Ok(())
    }

    /// Constrain squeezing new challenge
    pub fn squeeze(
        &mut self,
        ctx: &mut RegionCtx<'_, N>,
        num_outputs: usize,
    ) -> Result<Vec<AssignedValue<N>>, Error> {
        self.hasher_chip.squeeze(ctx, num_outputs)
    }
}
