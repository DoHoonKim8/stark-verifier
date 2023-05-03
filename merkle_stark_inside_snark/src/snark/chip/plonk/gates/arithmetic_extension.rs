use std::ops::{RangeBounds, Range};

use halo2curves::FieldExt;
use halo2wrong::RegionCtx;

use crate::snark::{chip::goldilocks_chip::GoldilocksChipConfig, types::assigned::{AssignedExtensionFieldValue, AssignedHashValues}};

use super::CustomGateConstrainer;



/// A gate which can perform a weighted multiply-add, i.e. `result = c0 x y + c1 z`. If the config
/// supports enough routed wires, it can support several such operations in one gate.
#[derive(Debug, Clone)]
pub struct ArithmeticExtensionGateConstrainer {
    /// Number of arithmetic operations performed by an arithmetic gate.
    pub num_ops: usize,
}

impl ArithmeticExtensionGateConstrainer {
    pub fn wires_ith_multiplicand_0(i: usize) -> Range<usize> {
        4 * 2 * i..4 * 2 * i + 2
    }
    pub fn wires_ith_multiplicand_1(i: usize) -> Range<usize> {
        4 * 2 * i + 2..4 * 2 * i + 2 * 2
    }
    pub fn wires_ith_addend(i: usize) -> Range<usize> {
        4 * 2 * i + 2 * 2..4 * 2 * i + 3 * 2
    }
    pub fn wires_ith_output(i: usize) -> Range<usize> {
        4 * 2 * i + 3 * 2..4 * 2 * i + 4 * 2
    }
}

impl<F: FieldExt> CustomGateConstrainer<F> for ArithmeticExtensionGateConstrainer {
    fn eval_unfiltered_constraint(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        goldilocks_chip_config: &GoldilocksChipConfig<F>,
        local_constants: &[AssignedExtensionFieldValue<F, 2>],
        local_wires: &[AssignedExtensionFieldValue<F, 2>],
        public_inputs_hash: &AssignedHashValues<F>,
    ) -> Result<Vec<AssignedExtensionFieldValue<F, 2>>, halo2_proofs::plonk::Error> {
        let goldilocks_extension_chip = self.goldilocks_extension_chip(goldilocks_chip_config);
        let const_0 = &local_constants[0];
        let const_1 = &local_constants[1];

        let mut constraints = Vec::new();
        for i in 0..self.num_ops {
            let multiplicand_0 = &local_wires[Self::wires_ith_multiplicand_0(i)][0];
            let multiplicand_1 = &local_wires[Self::wires_ith_multiplicand_1(i)][0];
            let addend = &local_wires[Self::wires_ith_addend(i)][0];
            let output = &local_wires[Self::wires_ith_output(i)][0];
            let computed_output = {
                let mul = goldilocks_extension_chip.mul_extension(ctx, multiplicand_0, multiplicand_1)?;
                let scaled_mul = goldilocks_extension_chip.mul_extension(ctx, const_0, &mul)?;
                goldilocks_extension_chip.mul_add_extension(ctx, const_1, addend, &scaled_mul)?
            };

            let diff = goldilocks_extension_chip.sub_extension(ctx, output, &computed_output)?;
            constraints.push(diff);
        }

        Ok(constraints)
    }
}
