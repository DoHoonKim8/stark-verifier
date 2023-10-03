use halo2_proofs::arithmetic::Field;
use halo2curves::{goldilocks::fp::Goldilocks, FieldExt};
use itertools::Itertools;
use plonky2::util::ceil_div_usize;

use crate::snark::{
    chip::{
        goldilocks_chip::GoldilocksChipConfig, goldilocks_extension_chip::GoldilocksExtensionChip,
    },
    types::assigned::AssignedExtensionFieldValue,
};

use super::CustomGateConstrainer;

/// A gate which takes a single constant parameter and outputs that value.
#[derive(Copy, Clone, Debug)]
pub struct U32AddManyGateConstrainer {
    pub num_addends: usize,
    pub num_ops: usize,
}

const LOG2_MAX_NUM_ADDENDS: usize = 4;
const MAX_NUM_ADDENDS: usize = 16;

impl U32AddManyGateConstrainer {
    pub fn wire_ith_op_jth_addend(&self, i: usize, j: usize) -> usize {
        debug_assert!(i < self.num_ops);
        debug_assert!(j < self.num_addends);
        (self.num_addends + 3) * i + j
    }
    pub fn wire_ith_carry(&self, i: usize) -> usize {
        debug_assert!(i < self.num_ops);
        (self.num_addends + 3) * i + self.num_addends
    }

    pub fn wire_ith_output_result(&self, i: usize) -> usize {
        debug_assert!(i < self.num_ops);
        (self.num_addends + 3) * i + self.num_addends + 1
    }
    pub fn wire_ith_output_carry(&self, i: usize) -> usize {
        debug_assert!(i < self.num_ops);
        (self.num_addends + 3) * i + self.num_addends + 2
    }

    pub fn limb_bits() -> usize {
        2
    }
    pub fn num_result_limbs() -> usize {
        ceil_div_usize(32, Self::limb_bits())
    }
    pub fn num_carry_limbs() -> usize {
        ceil_div_usize(LOG2_MAX_NUM_ADDENDS, Self::limb_bits())
    }
    pub fn num_limbs() -> usize {
        Self::num_result_limbs() + Self::num_carry_limbs()
    }

    pub fn wire_ith_output_jth_limb(&self, i: usize, j: usize) -> usize {
        debug_assert!(i < self.num_ops);
        debug_assert!(j < Self::num_limbs());
        (self.num_addends + 3) * self.num_ops + Self::num_limbs() * i + j
    }
}

impl<F: FieldExt> CustomGateConstrainer<F> for U32AddManyGateConstrainer {
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
        let mut constraints: Vec<AssignedExtensionFieldValue<F, 2>> = Vec::new();

        let goldilocks_extension_chip = self.goldilocks_extension_chip(goldilocks_chip_config);

        for i in 0..self.num_ops {
            let addends = (0..self.num_addends)
                .map(|j| &local_wires[self.wire_ith_op_jth_addend(i, j)])
                .cloned()
                .collect_vec();

            let carry = &local_wires[self.wire_ith_carry(i)];

            let one = goldilocks_extension_chip.one_extension(ctx)?;

            let sum = goldilocks_extension_chip.reduce_extension(ctx, &one, &addends)?;

            let computed_output = goldilocks_extension_chip.add_extension(ctx, &sum, &carry)?;

            let output_result = &local_wires[self.wire_ith_output_result(i)];
            let output_carry = &local_wires[self.wire_ith_output_carry(i)];

            let base = goldilocks_extension_chip
                .constant_extension(ctx, &[Goldilocks::from(1 << 32u64), Goldilocks::zero()])?;

            let temp_mul = goldilocks_extension_chip.mul_extension(ctx, &output_carry, &base)?;

            let combined_output =
                goldilocks_extension_chip.add_extension(ctx, &temp_mul, &output_result)?;

            constraints.push(goldilocks_extension_chip.sub_extension(
                ctx,
                &combined_output,
                &computed_output,
            )?);

            let mut combined_result_limbs = goldilocks_extension_chip.zero_extension(ctx)?;
            let mut combined_carry_limbs = goldilocks_extension_chip.zero_extension(ctx)?;
            let base = goldilocks_extension_chip.constant_extension(
                ctx,
                &[
                    Goldilocks::from(1u64 << Self::limb_bits()),
                    Goldilocks::zero(),
                ],
            )?;

            for j in (0..Self::num_limbs()).rev() {
                let this_limb = &local_wires[self.wire_ith_output_jth_limb(i, j)];
                let max_limb = 1 << Self::limb_bits();
                // TODO:

                let mut product = goldilocks_extension_chip.one_extension(ctx)?;

                for x in 0..max_limb {
                    let x_value = goldilocks_extension_chip
                        .constant_extension(ctx, &[Goldilocks::from(x), Goldilocks::zero()])?;

                    let temp =
                        goldilocks_extension_chip.sub_extension(ctx, &this_limb, &x_value)?;

                    product = goldilocks_extension_chip.mul_extension(ctx, &product, &temp)?;
                }

                constraints.push(product);

                if j < Self::num_result_limbs() {
                    let mul = goldilocks_extension_chip.mul_extension(
                        ctx,
                        &base,
                        &combined_result_limbs,
                    )?;
                    combined_result_limbs =
                        goldilocks_extension_chip.add_extension(ctx, &mul, &this_limb)?;
                } else {
                    let mul = goldilocks_extension_chip.mul_extension(
                        ctx,
                        &base,
                        &combined_carry_limbs,
                    )?;
                    combined_carry_limbs =
                        goldilocks_extension_chip.add_extension(ctx, &mul, &this_limb)?;
                }
            }
            constraints.push(goldilocks_extension_chip.sub_extension(
                ctx,
                &combined_result_limbs,
                &output_result,
            )?);
            constraints.push(goldilocks_extension_chip.sub_extension(
                ctx,
                &combined_carry_limbs,
                &output_carry,
            )?);
        }

        Ok(constraints)
    }
}
