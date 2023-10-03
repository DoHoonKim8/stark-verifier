use halo2_proofs::arithmetic::Field;
use halo2curves::{goldilocks::fp::Goldilocks, FieldExt};

use crate::snark::chip::{
    goldilocks_chip::GoldilocksChipConfig, goldilocks_extension_chip::GoldilocksExtensionChip,
};

use super::CustomGateConstrainer;

/// A gate which takes a single constant parameter and outputs that value.
#[derive(Copy, Clone, Debug)]
pub struct U32ArithmeticGateConstrainer {
    pub num_ops: usize,
}

impl U32ArithmeticGateConstrainer {
    pub fn wire_ith_multiplicand_0(&self, i: usize) -> usize {
        debug_assert!(i < self.num_ops);
        Self::routed_wires_per_op() * i
    }
    pub fn wire_ith_multiplicand_1(&self, i: usize) -> usize {
        debug_assert!(i < self.num_ops);
        Self::routed_wires_per_op() * i + 1
    }
    pub fn wire_ith_addend(&self, i: usize) -> usize {
        debug_assert!(i < self.num_ops);
        Self::routed_wires_per_op() * i + 2
    }

    pub fn wire_ith_output_low_half(&self, i: usize) -> usize {
        debug_assert!(i < self.num_ops);
        Self::routed_wires_per_op() * i + 3
    }

    pub fn wire_ith_output_high_half(&self, i: usize) -> usize {
        debug_assert!(i < self.num_ops);
        Self::routed_wires_per_op() * i + 4
    }

    pub fn wire_ith_inverse(&self, i: usize) -> usize {
        debug_assert!(i < self.num_ops);
        Self::routed_wires_per_op() * i + 5
    }

    pub fn limb_bits() -> usize {
        2
    }
    pub fn num_limbs() -> usize {
        64 / Self::limb_bits()
    }
    pub fn routed_wires_per_op() -> usize {
        6
    }
    pub fn wire_ith_output_jth_limb(&self, i: usize, j: usize) -> usize {
        debug_assert!(i < self.num_ops);
        debug_assert!(j < Self::num_limbs());
        Self::routed_wires_per_op() * self.num_ops + Self::num_limbs() * i + j
    }
}

impl<F: FieldExt> CustomGateConstrainer<F> for U32ArithmeticGateConstrainer {
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
        let mut constraints = Vec::new();

        let goldilocks_extension_chip = self.goldilocks_extension_chip(goldilocks_chip_config);

        for i in 0..self.num_ops {
            let multiplicand_0 = &local_wires[self.wire_ith_multiplicand_0(i)];
            let multiplicand_1 = &local_wires[self.wire_ith_multiplicand_1(i)];
            let addend = &local_wires[self.wire_ith_addend(i)];

            let computed_output = goldilocks_extension_chip.mul_add_extension(
                ctx,
                multiplicand_0,
                multiplicand_1,
                addend,
            )?;

            let output_low = &local_wires[self.wire_ith_output_low_half(i)];
            let output_high = &local_wires[self.wire_ith_output_high_half(i)];
            let inverse = &local_wires[self.wire_ith_inverse(i)];

            // Check canonicity of combined_output = output_high * 2^32 + output_low
            let combined_output = {
                let base = goldilocks_extension_chip
                    .constant_extension(ctx, &[Goldilocks::from(1 << 32u64), Goldilocks::zero()])?;
                let one = goldilocks_extension_chip.one_extension(ctx)?;
                let u32_max = goldilocks_extension_chip.constant_extension(
                    ctx,
                    &[Goldilocks::from(u32::MAX as u64), Goldilocks::zero()],
                )?;

                // This is zero if and only if the high limb is `u32::MAX`.
                // u32::MAX - output_high
                let diff = goldilocks_extension_chip.sub_extension(ctx, &u32_max, &output_high)?;
                // If this is zero, the diff is invertible, so the high limb is not `u32::MAX`.
                // inverse * diff - 1
                let mul = goldilocks_extension_chip.mul_extension(ctx, inverse, &diff)?;
                let hi_not_max = goldilocks_extension_chip.sub_extension(ctx, &mul, &one)?;
                // If this is zero, either the high limb is not `u32::MAX`, or the low limb is zero.
                // hi_not_max * limb_0_u32
                let hi_not_max_or_lo_zero =
                    goldilocks_extension_chip.mul_extension(ctx, &hi_not_max, output_low)?;

                constraints.push(hi_not_max_or_lo_zero);

                goldilocks_extension_chip.mul_add_extension(ctx, output_high, &base, output_low)?
            };

            constraints.push(goldilocks_extension_chip.sub_extension(
                ctx,
                &combined_output,
                &computed_output,
            )?);

            let mut combined_low_limbs = goldilocks_extension_chip.zero_extension(ctx)?;
            let mut combined_high_limbs = goldilocks_extension_chip.zero_extension(ctx)?;
            let midpoint = Self::num_limbs() / 2;
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

                let mut product = goldilocks_extension_chip.one_extension(ctx)?;

                for x in 0..max_limb {
                    let x = goldilocks_extension_chip
                        .constant_extension(ctx, &[Goldilocks::from(x), Goldilocks::zero()])?;

                    let diff = goldilocks_extension_chip.sub_extension(ctx, &this_limb, &x)?;

                    product = goldilocks_extension_chip.mul_extension(ctx, &product, &diff)?;
                }

                constraints.push(product);

                if j < midpoint {
                    combined_low_limbs = goldilocks_extension_chip.mul_add_extension(
                        ctx,
                        &base,
                        &combined_low_limbs,
                        &this_limb,
                    )?;
                } else {
                    combined_high_limbs = goldilocks_extension_chip.mul_add_extension(
                        ctx,
                        &base,
                        &combined_high_limbs,
                        &this_limb,
                    )?;
                }
            }
            constraints.push(goldilocks_extension_chip.sub_extension(
                ctx,
                &combined_low_limbs,
                output_low,
            )?);
            constraints.push(goldilocks_extension_chip.sub_extension(
                ctx,
                &combined_high_limbs,
                output_high,
            )?);
        }

        Ok(constraints)
    }
}
