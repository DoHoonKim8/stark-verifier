use std::ops::Range;

use crate::plonky2_verifier::context::RegionCtx;
use halo2_proofs::halo2curves::ff::PrimeField;

use crate::plonky2_verifier::{
    chip::goldilocks_chip::GoldilocksChipConfig,
    types::assigned::{AssignedExtensionFieldValue, AssignedHashValues},
};

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

impl<F: PrimeField> CustomGateConstrainer<F> for ArithmeticExtensionGateConstrainer {
    fn eval_unfiltered_constraint(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        goldilocks_chip_config: &GoldilocksChipConfig<F>,
        local_constants: &[AssignedExtensionFieldValue<F, 2>],
        local_wires: &[AssignedExtensionFieldValue<F, 2>],
        _public_inputs_hash: &AssignedHashValues<F>,
    ) -> Result<Vec<AssignedExtensionFieldValue<F, 2>>, halo2_proofs::plonk::Error> {
        let goldilocks_extension_algebra_chip =
            self.goldilocks_extension_algebra_chip(goldilocks_chip_config);
        let const_0 = &local_constants[0];
        let const_1 = &local_constants[1];

        let mut constraints = Vec::new();
        for i in 0..self.num_ops {
            let multiplicand_0 =
                self.get_local_ext_algebra(local_wires, Self::wires_ith_multiplicand_0(i));
            let multiplicand_1 =
                self.get_local_ext_algebra(local_wires, Self::wires_ith_multiplicand_1(i));
            let addend = self.get_local_ext_algebra(local_wires, Self::wires_ith_addend(i));
            let output = self.get_local_ext_algebra(local_wires, Self::wires_ith_output(i));
            let computed_output = {
                let mul = goldilocks_extension_algebra_chip.mul_ext_algebra(
                    ctx,
                    &multiplicand_0,
                    &multiplicand_1,
                )?;
                let scaled_mul =
                    goldilocks_extension_algebra_chip.scalar_mul_ext_algebra(ctx, const_0, &mul)?;
                goldilocks_extension_algebra_chip.scalar_mul_add_ext_algebra(
                    ctx,
                    const_1,
                    &addend,
                    &scaled_mul,
                )?
            };

            let diff = goldilocks_extension_algebra_chip.sub_ext_algebra(
                ctx,
                &output,
                &computed_output,
            )?;
            constraints.extend(diff.to_ext_array());
        }
        Ok(constraints)
    }
}

#[cfg(test)]
mod tests {

    use crate::plonky2_verifier::chip::plonk::gates::gate_test::test_custom_gate;
    use plonky2::{
        gates::arithmetic_extension::ArithmeticExtensionGate, plonk::circuit_data::CircuitConfig,
    };

    use super::ArithmeticExtensionGateConstrainer;

    #[test]
    fn test_arithmetic_extension_gate() {
        let plonky2_gate =
            ArithmeticExtensionGate::new_from_config(&CircuitConfig::standard_recursion_config());
        let halo2_gate = ArithmeticExtensionGateConstrainer {
            num_ops: plonky2_gate.num_ops,
        };
        test_custom_gate(plonky2_gate, halo2_gate, 17);
    }
}
