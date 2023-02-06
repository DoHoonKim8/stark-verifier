use halo2_proofs::arithmetic::Field;
use halo2_proofs::plonk::Error;
use halo2curves::goldilocks::fp::Goldilocks;
use halo2wrong::RegionCtx;
use halo2wrong_maingate::{MainGateConfig, MainGateInstructions, AssignedValue};

use crate::snark::verifier_circuit::Verifier;
use crate::snark::types::assigned::AssignedExtensionFieldValue;

impl Verifier {
    /// const_0 * multiplicand_0 * multiplicand_1 + const_1 * addend
    pub fn arithmetic_extension(
        &self,
        ctx: &mut RegionCtx<'_, Goldilocks>,
        main_gate_config: &MainGateConfig,
        const_0: Goldilocks,
        const_1: Goldilocks,
        multiplicand_0: AssignedExtensionFieldValue<Goldilocks, 2>,
        multiplicand_1: AssignedExtensionFieldValue<Goldilocks, 2>,
        addend: AssignedExtensionFieldValue<Goldilocks, 2>,
    ) -> Result<AssignedExtensionFieldValue<Goldilocks, 2>, Error> {
        let main_gate = self.main_gate(main_gate_config);
        todo!()
    }

    pub fn zero_extension(
        &self,
        ctx: &mut RegionCtx<'_, Goldilocks>,
        main_gate_config: &MainGateConfig,
    ) -> Result<AssignedExtensionFieldValue<Goldilocks, 2>, Error> {
        let main_gate = self.main_gate(main_gate_config);
        let elements = (0..2)
            .map(|i| main_gate.assign_constant(ctx, Goldilocks::zero()))
            .collect::<Result<Vec<AssignedValue<Goldilocks>>, Error>>()?;
        Ok(AssignedExtensionFieldValue(elements.try_into().unwrap()))
    }

    pub fn mul_extension_with_const(
        &self,
        ctx: &mut RegionCtx<'_, Goldilocks>,
        main_gate_config: &MainGateConfig,
        const_0: Goldilocks,
        multiplicand_0: AssignedExtensionFieldValue<Goldilocks, 2>,
        multiplicand_1: AssignedExtensionFieldValue<Goldilocks, 2>,
    ) -> Result<AssignedExtensionFieldValue<Goldilocks, 2>, Error> {
        let zero = self.zero_extension(ctx, main_gate_config)?;
        self.arithmetic_extension(
            ctx,
            main_gate_config,
            const_0,
            Goldilocks::zero(),
            multiplicand_0,
            multiplicand_1,
            zero
        )
    }

    pub fn mul_extension(
        &self,
        ctx: &mut RegionCtx<'_, Goldilocks>,
        main_gate_config: &MainGateConfig,
        multiplicand_0: AssignedExtensionFieldValue<Goldilocks, 2>,
        multiplicand_1: AssignedExtensionFieldValue<Goldilocks, 2>,
    ) -> Result<AssignedExtensionFieldValue<Goldilocks, 2>, Error> {
        self.mul_extension_with_const(
            ctx,
            main_gate_config,
            Goldilocks::one(),
            multiplicand_0,
            multiplicand_1
        )
    }

    pub fn square_extension(
        &self,
        ctx: &mut RegionCtx<'_, Goldilocks>,
        main_gate_config: &MainGateConfig,
        x: AssignedExtensionFieldValue<Goldilocks, 2>
    ) -> Result<AssignedExtensionFieldValue<Goldilocks, 2>, Error> {
        self.mul_extension(ctx, main_gate_config, x, x)
    }
}
