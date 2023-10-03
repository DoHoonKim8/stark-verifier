use halo2_proofs::arithmetic::Field;
use halo2curves::{goldilocks::fp::Goldilocks, FieldExt};
use itertools::Itertools;
use plonky2::{
    field::types::Field64,
    util::{bits_u64, ceil_div_usize},
};

use crate::snark::{
    chip::{
        goldilocks_chip::GoldilocksChipConfig, goldilocks_extension_chip::GoldilocksExtensionChip,
    },
    types::assigned::AssignedExtensionFieldValue,
};

use super::CustomGateConstrainer;

/// A gate which takes a single constant parameter and outputs that value.
#[derive(Copy, Clone, Debug)]
pub struct ComparisonGateContainer {
    pub num_bits: usize,
    pub num_chunks: usize,
}

impl ComparisonGateContainer {
    pub fn new(num_bits: usize, num_chunks: usize) -> Self {
        debug_assert!(
            num_bits < bits_u64(plonky2::field::goldilocks_field::GoldilocksField::ORDER)
        );
        Self {
            num_bits,
            num_chunks,
        }
    }

    pub fn chunk_bits(&self) -> usize {
        ceil_div_usize(self.num_bits, self.num_chunks)
    }

    pub fn wire_first_input(&self) -> usize {
        0
    }

    pub fn wire_second_input(&self) -> usize {
        1
    }

    pub fn wire_result_bool(&self) -> usize {
        2
    }

    pub fn wire_most_significant_diff(&self) -> usize {
        3
    }

    pub fn wire_first_chunk_val(&self, chunk: usize) -> usize {
        debug_assert!(chunk < self.num_chunks);
        4 + chunk
    }

    pub fn wire_second_chunk_val(&self, chunk: usize) -> usize {
        debug_assert!(chunk < self.num_chunks);
        4 + self.num_chunks + chunk
    }

    pub fn wire_equality_dummy(&self, chunk: usize) -> usize {
        debug_assert!(chunk < self.num_chunks);
        4 + 2 * self.num_chunks + chunk
    }

    pub fn wire_chunks_equal(&self, chunk: usize) -> usize {
        debug_assert!(chunk < self.num_chunks);
        4 + 3 * self.num_chunks + chunk
    }

    pub fn wire_intermediate_value(&self, chunk: usize) -> usize {
        debug_assert!(chunk < self.num_chunks);
        4 + 4 * self.num_chunks + chunk
    }

    /// The `bit_index`th bit of 2^n - 1 + most_significant_diff.
    pub fn wire_most_significant_diff_bit(&self, bit_index: usize) -> usize {
        4 + 5 * self.num_chunks + bit_index
    }
}

impl<F: FieldExt> CustomGateConstrainer<F> for ComparisonGateContainer {
    fn eval_unfiltered_constraint(
        &self,
        ctx: &mut halo2wrong::RegionCtx<'_, F>,
        goldilocks_chip_config: &GoldilocksChipConfig<F>,
        local_constants: &[crate::snark::types::assigned::AssignedExtensionFieldValue<F, 2>],
        local_wires: &[crate::snark::types::assigned::AssignedExtensionFieldValue<F, 2>],
        public_inputs_hash: &crate::snark::types::assigned::AssignedHashValues<F>,
    ) -> Result<
        Vec<crate::snark::types::assigned::AssignedExtensionFieldValue<F, 2>>,
        halo2_proofs::plonk::Error,
    > {
        // let mut constraints = Vec::with_capacity(self.num_constraints());
        let mut constraints: Vec<AssignedExtensionFieldValue<F, 2>> = vec![];
        let goldilocks_extension_chip = self.goldilocks_extension_chip(goldilocks_chip_config);

        let first_input = &local_wires[self.wire_first_input()];
        let second_input = &local_wires[self.wire_second_input()];

        // Get chunks and assert that they match
        let first_chunks = (0..self.num_chunks)
            .map(|i| &local_wires[self.wire_first_chunk_val(i)])
            .cloned()
            .collect_vec();

        let second_chunks = (0..self.num_chunks)
            .map(|i| &local_wires[self.wire_second_chunk_val(i)])
            .cloned()
            .collect_vec();

        let chunk_base = &goldilocks_extension_chip.constant_extension(
            ctx,
            &[Goldilocks::from(1 << self.chunk_bits()), Goldilocks::zero()],
        )?;

        let first_chunks_combined =
            goldilocks_extension_chip.reduce_extension(ctx, &chunk_base, &first_chunks)?;

        let second_chunks_combined =
            goldilocks_extension_chip.reduce_extension(ctx, &chunk_base, &second_chunks)?;

        constraints.push(goldilocks_extension_chip.sub_extension(
            ctx,
            &first_chunks_combined,
            &first_input,
        )?);

        constraints.push(goldilocks_extension_chip.sub_extension(
            ctx,
            &second_chunks_combined,
            &second_input,
        )?);

        let chunk_size = 1 << self.chunk_bits();

        let mut most_significant_diff_so_far = goldilocks_extension_chip.zero_extension(ctx)?;

        let one = goldilocks_extension_chip.one_extension(ctx)?;

        for i in 0..self.num_chunks {
            // Range-check the chunks to be less than `chunk_size`.
            let mut first_product = one.clone();
            let mut second_product = one.clone();

            for x in 0..chunk_size {
                let x_f = goldilocks_extension_chip
                    .constant_extension(ctx, &[Goldilocks::from(x), Goldilocks::zero()])?;

                let first_diff =
                    goldilocks_extension_chip.sub_extension(ctx, &first_chunks[i], &x_f)?;

                let second_diff =
                    goldilocks_extension_chip.sub_extension(ctx, &second_chunks[i], &x_f)?;

                first_product =
                    goldilocks_extension_chip.mul_extension(ctx, &first_product, &first_diff)?;

                second_product =
                    goldilocks_extension_chip.mul_extension(ctx, &second_product, &second_diff)?;
            }

            constraints.push(first_product);
            constraints.push(second_product);

            let difference = goldilocks_extension_chip.sub_extension(
                ctx,
                &second_chunks[i],
                &first_chunks[i],
            )?;

            let equality_dummy = &local_wires[self.wire_equality_dummy(i)];
            let chunks_equal = &local_wires[self.wire_chunks_equal(i)];

            let diff_times_equal =
                goldilocks_extension_chip.mul_extension(ctx, &difference, &equality_dummy)?;

            let not_equal = goldilocks_extension_chip.sub_extension(ctx, &one, &chunks_equal)?;

            // Two constraints to assert that `chunks_equal` is valid.
            constraints.push(goldilocks_extension_chip.sub_extension(ctx, &diff_times_equal, &not_equal)?);
            constraints.push(goldilocks_extension_chip.mul_extension(
                ctx,
                &chunks_equal,
                &difference,
            )?);

            // Update `most_significant_diff_so_far`.
            let intermediate_value = &local_wires[self.wire_intermediate_value(i)];

            let old_diff = goldilocks_extension_chip.mul_extension(
                ctx,
                &chunks_equal,
                &most_significant_diff_so_far,
            )?;

            constraints.push(goldilocks_extension_chip.sub_extension(
                ctx,
                &intermediate_value,
                &old_diff,
            )?);

            let not_equal = goldilocks_extension_chip.sub_extension(ctx, &one, &chunks_equal)?;
            let new_diff = goldilocks_extension_chip.mul_extension(ctx, &not_equal, &difference)?;

            most_significant_diff_so_far =
                goldilocks_extension_chip.add_extension(ctx, &intermediate_value, &new_diff)?;
        }

        let most_significant_diff = &local_wires[self.wire_most_significant_diff()];
        constraints.push(goldilocks_extension_chip.sub_extension(
            ctx,
            most_significant_diff,
            &most_significant_diff_so_far,
        )?);

        let most_significant_diff_bits: Vec<_> = (0..self.chunk_bits() + 1)
            .map(|i| &local_wires[self.wire_most_significant_diff_bit(i)])
            .cloned()
            .collect();

        let one = goldilocks_extension_chip.one_extension(ctx)?;

        // Range-check the bits.
        for this_bit in &most_significant_diff_bits {
            let inverse = goldilocks_extension_chip.sub_extension(ctx, &one, &this_bit)?;

            constraints.push(goldilocks_extension_chip.mul_extension(ctx, &this_bit, &inverse)?);
        }

        let two = goldilocks_extension_chip.two_extension(ctx)?;
        let bits_combined =
            goldilocks_extension_chip.reduce_extension(ctx, &two, &most_significant_diff_bits)?;

        let two_n = goldilocks_extension_chip.constant_extension(
            ctx,
            &[Goldilocks::from(1 << self.chunk_bits()), Goldilocks::zero()],
        )?;

        let sum =
            goldilocks_extension_chip.add_extension(ctx, &two_n, &most_significant_diff)?;

        constraints.push(goldilocks_extension_chip.sub_extension(
            ctx,
            &sum,
            &bits_combined,
        )?);

        // Iff first <= second, the top (n + 1st) bit of (2^n + most_significant_diff) will be 1.
        let result_bool = &local_wires[self.wire_result_bool()];
        constraints.push(goldilocks_extension_chip.sub_extension(
            ctx,
            &result_bool,
            &most_significant_diff_bits[self.chunk_bits()],
        )?);

        Ok(constraints)
    }
}
