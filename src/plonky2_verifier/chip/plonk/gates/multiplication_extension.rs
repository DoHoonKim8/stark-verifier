use std::ops::Range;

use crate::plonky2_verifier::context::RegionCtx;
use halo2_proofs::{halo2curves::ff::PrimeField, plonk::Error};

use crate::plonky2_verifier::{
    chip::goldilocks_chip::GoldilocksChipConfig,
    types::assigned::{AssignedExtensionFieldValue, AssignedHashValues},
};

use super::CustomGateConstrainer;

/// A gate which can perform a weighted multiplication, i.e. `result = c0 x y`. If the config
/// supports enough routed wires, it can support several such operations in one gate.
#[derive(Debug, Clone)]
pub struct MulExtensionGateConstrainer {
    /// Number of multiplications performed by the gate.
    pub num_ops: usize,
}

impl MulExtensionGateConstrainer {
    pub fn wires_ith_multiplicand_0(i: usize) -> Range<usize> {
        3 * 2 * i..3 * 2 * i + 2
    }
    pub fn wires_ith_multiplicand_1(i: usize) -> Range<usize> {
        3 * 2 * i + 2..3 * 2 * i + 2 * 2
    }
    pub fn wires_ith_output(i: usize) -> Range<usize> {
        3 * 2 * i + 2 * 2..3 * 2 * i + 3 * 2
    }
}

impl<F: PrimeField> CustomGateConstrainer<F> for MulExtensionGateConstrainer {
    fn eval_unfiltered_constraint(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        goldilocks_chip_config: &GoldilocksChipConfig<F>,
        local_constants: &[AssignedExtensionFieldValue<F, 2>],
        local_wires: &[AssignedExtensionFieldValue<F, 2>],
        _public_inputs_hash: &AssignedHashValues<F>,
    ) -> Result<Vec<AssignedExtensionFieldValue<F, 2>>, Error> {
        let goldilocks_extension_algebra_chip =
            self.goldilocks_extension_algebra_chip(goldilocks_chip_config);
        let const_0 = &local_constants[0];

        let mut constraints = Vec::new();
        for i in 0..self.num_ops {
            let multiplicand_0 =
                self.get_local_ext_algebra(local_wires, Self::wires_ith_multiplicand_0(i));
            let multiplicand_1 =
                self.get_local_ext_algebra(local_wires, Self::wires_ith_multiplicand_1(i));
            let output = self.get_local_ext_algebra(local_wires, Self::wires_ith_output(i));
            let computed_output = {
                let mul = goldilocks_extension_algebra_chip.mul_ext_algebra(
                    ctx,
                    &multiplicand_0,
                    &multiplicand_1,
                )?;
                goldilocks_extension_algebra_chip.scalar_mul_ext_algebra(ctx, const_0, &mul)?
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
    use super::MulExtensionGateConstrainer;
    use crate::plonky2_verifier::chip::plonk::gates::gate_test::test_custom_gate;
    use plonky2::{
        gates::multiplication_extension::MulExtensionGate, plonk::circuit_data::CircuitConfig,
    };

    #[test]
    fn test_mul_extension_gate() {
        let plonky2_gate =
            MulExtensionGate::new_from_config(&CircuitConfig::standard_recursion_config());
        let halo2_gate = MulExtensionGateConstrainer {
            num_ops: plonky2_gate.num_ops,
        };
        test_custom_gate(plonky2_gate, halo2_gate, 17);
    }
}
