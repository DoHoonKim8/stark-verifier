use halo2_proofs::plonk::Error;
use halo2curves::goldilocks::fp::Goldilocks;
use halo2wrong::RegionCtx;
use halo2wrong_maingate::MainGateConfig;

use crate::snark::{
    goldilocks_extension_chip::GoldilocksExtensionChip,
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

impl CustomGateConstrainer for ArithmeticGateConstrainer {
    fn eval_unfiltered_constraint(
        &self,
        ctx: &mut RegionCtx<'_, Goldilocks>,
        main_gate_config: &MainGateConfig,
        local_constants: &[AssignedExtensionFieldValue<Goldilocks, 2>],
        local_wires: &[AssignedExtensionFieldValue<Goldilocks, 2>],
        public_inputs_hash: &AssignedHashValues<Goldilocks>,
    ) -> Result<Vec<AssignedExtensionFieldValue<Goldilocks, 2>>, Error> {
        let goldilocks_extension_chip = GoldilocksExtensionChip::new(main_gate_config);
        let const_0 = &local_constants[0];
        let const_1 = &local_constants[1];

        let mut constraints = vec![];
        for i in 0..self.num_ops {
            let multiplicand_0 = &local_wires[Self::wires_ith_multiplicand_0(i)];
            let multiplicand_1 = &local_wires[Self::wires_ith_multiplicand_1(i)];
            let addend = &local_wires[Self::wires_ith_addend(i)];
            let output = &local_wires[Self::wires_ith_output(i)];

            let term1 = goldilocks_extension_chip.mul(ctx, multiplicand_0, multiplicand_1)?;
            let term1 = goldilocks_extension_chip.mul(ctx, &term1, const_0)?;
            let term2 = goldilocks_extension_chip.mul(ctx, addend, const_1)?;
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
