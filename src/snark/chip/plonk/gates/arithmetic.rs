use crate::snark::context::RegionCtx;
use halo2_proofs::{halo2curves::ff::PrimeField, plonk::Error};

use crate::snark::{
    chip::{
        goldilocks_chip::GoldilocksChipConfig, goldilocks_extension_chip::GoldilocksExtensionChip,
    },
    types::assigned::{AssignedExtensionFieldValue, AssignedHashValues},
};

use super::CustomGateConstrainer;

#[derive(Debug, Clone)]
pub struct ArithmeticGateConstrainer {
    /// Number of arithmetic operations performed by an arithmetic gate.
    pub num_ops: usize,
}

impl ArithmeticGateConstrainer {
    fn wires_ith_multiplicand_0(i: usize) -> usize {
        4 * i
    }

    fn wires_ith_multiplicand_1(i: usize) -> usize {
        4 * i + 1
    }

    fn wires_ith_addend(i: usize) -> usize {
        4 * i + 2
    }

    fn wires_ith_output(i: usize) -> usize {
        4 * i + 3
    }
}

impl<F: PrimeField> CustomGateConstrainer<F> for ArithmeticGateConstrainer {
    fn eval_unfiltered_constraint(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        goldilocks_chip_config: &GoldilocksChipConfig<F>,
        local_constants: &[AssignedExtensionFieldValue<F, 2>],
        local_wires: &[AssignedExtensionFieldValue<F, 2>],
        _public_inputs_hash: &AssignedHashValues<F>,
    ) -> Result<Vec<AssignedExtensionFieldValue<F, 2>>, Error> {
        let goldilocks_extension_chip = GoldilocksExtensionChip::new(goldilocks_chip_config);
        let const_0 = &local_constants[0];
        let const_1 = &local_constants[1];

        let mut constraints = vec![];
        for i in 0..self.num_ops {
            let multiplicand_0 = &local_wires[Self::wires_ith_multiplicand_0(i)];
            let multiplicand_1 = &local_wires[Self::wires_ith_multiplicand_1(i)];
            let addend = &local_wires[Self::wires_ith_addend(i)];
            let output = &local_wires[Self::wires_ith_output(i)];

            let term1 =
                goldilocks_extension_chip.mul_extension(ctx, multiplicand_0, multiplicand_1)?;
            let term1 = goldilocks_extension_chip.mul_extension(ctx, &term1, const_0)?;
            let term2 = goldilocks_extension_chip.mul_extension(ctx, addend, const_1)?;
            let computed_output = goldilocks_extension_chip.add_extension(ctx, &term1, &term2)?;

            constraints.push(goldilocks_extension_chip.sub_extension(
                ctx,
                &output,
                &computed_output,
            )?);
        }

        Ok(constraints)
    }
}

#[cfg(test)]
mod tests {
    use super::ArithmeticGateConstrainer;
    use crate::snark::chip::plonk::gates::gate_test::test_custom_gate;
    use plonky2::{gates::arithmetic_base::ArithmeticGate, plonk::circuit_data::CircuitConfig};

    #[test]
    fn test_arithmetic_gate() {
        let plonky2_gate =
            ArithmeticGate::new_from_config(&CircuitConfig::standard_recursion_config());
        let halo2_gate = ArithmeticGateConstrainer {
            num_ops: plonky2_gate.num_ops,
        };
        test_custom_gate(plonky2_gate, halo2_gate, 17);
    }
}
