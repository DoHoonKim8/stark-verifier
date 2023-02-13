use halo2_proofs::arithmetic::Field;
use halo2_proofs::circuit::Value;
use halo2_proofs::plonk::Error;
use halo2curves::goldilocks::fp::Goldilocks;
use halo2wrong::RegionCtx;
use halo2wrong_maingate::{
    AssignedValue, CombinationOption, MainGateConfig, MainGateInstructions, Term,
};

use crate::snark::types::assigned::AssignedExtensionFieldValue;
use crate::snark::verifier_circuit::Verifier;

// Layouts Goldilocks quadratic extension field arithmetic constraints
impl Verifier {
    // lhs[0] * rhs[0] + w * lhs[1] * rhs[1] - res[0] = 0
    // lhs[0] * rhs[1] + lhs[1] * rhs[0] - res[1] = 0

    // Witness layout:
    // | A      | B      | C      | D      | E      |
    // | ---    | ---    | -      | ---    | ---    |
    // | lhs[0] | rhs[0] | lhs[1] | rhs[1] | res[0] |
    // | lhs[0] | rhs[1] | lhs[1] | rhs[0] | res[1] |
    fn mul(
        &self,
        ctx: &mut RegionCtx<'_, Goldilocks>,
        main_gate_config: &MainGateConfig,
        lhs: &AssignedExtensionFieldValue<Goldilocks, 2>,
        rhs: &AssignedExtensionFieldValue<Goldilocks, 2>,
    ) -> Result<AssignedExtensionFieldValue<Goldilocks, 2>, Error> {
        let main_gate = self.main_gate(main_gate_config);
        let zero = Goldilocks::zero();
        let one = Goldilocks::one();
        let w = Goldilocks::from(7);
        let mut res = [Value::unknown(); 2];
        res[0] = lhs.0[0].value().zip(rhs.0[0].value()).map(|(l, r)| *l * *r)
            + lhs.0[1].value().zip(rhs.0[1].value()).map(|(l, r)| *l * *r);
        res[1] = lhs.0[0].value().zip(rhs.0[1].value()).map(|(l, r)| *l * *r)
            + lhs.0[1].value().zip(rhs.0[0].value()).map(|(l, r)| *l * *r);

        let mut assigned_1 = main_gate.apply(
            ctx,
            [
                Term::assigned_to_mul(&lhs.0[0]),
                Term::assigned_to_mul(&rhs.0[0]),
                Term::assigned_to_mul(&lhs.0[1]),
                Term::assigned_to_mul(&rhs.0[1]),
                Term::unassigned_to_sub(res[0]),
            ],
            zero,
            CombinationOption::OneLinerDoubleMul(w),
        )?;

        let mut assigned_2 = main_gate.apply(
            ctx,
            [
                Term::assigned_to_mul(&lhs.0[0]),
                Term::assigned_to_mul(&rhs.0[1]),
                Term::assigned_to_mul(&lhs.0[1]),
                Term::assigned_to_mul(&rhs.0[0]),
                Term::unassigned_to_sub(res[1]),
            ],
            zero,
            CombinationOption::OneLinerDoubleMul(one),
        )?;
        let res =
            AssignedExtensionFieldValue([assigned_1.swap_remove(4), assigned_2.swap_remove(4)]);
        Ok(res)
    }

    fn add(
        &self,
        ctx: &mut RegionCtx<'_, Goldilocks>,
        main_gate_config: &MainGateConfig,
        addend_0: &AssignedExtensionFieldValue<Goldilocks, 2>,
        addend_1: &AssignedExtensionFieldValue<Goldilocks, 2>,
    ) -> Result<AssignedExtensionFieldValue<Goldilocks, 2>, Error> {
        let main_gate = self.main_gate(main_gate_config);
        let added = addend_0
            .0
            .iter()
            .zip(addend_1.0.iter())
            .map(|(addend_0, addend_1)| main_gate.add(ctx, addend_0, addend_1))
            .collect::<Result<Vec<AssignedValue<Goldilocks>>, Error>>()?;
        Ok(AssignedExtensionFieldValue(added.try_into().unwrap()))
    }

    fn scalar_mul(
        &self,
        ctx: &mut RegionCtx<'_, Goldilocks>,
        main_gate_config: &MainGateConfig,
        multiplicand: &AssignedExtensionFieldValue<Goldilocks, 2>,
        scalar: Goldilocks,
    ) -> Result<AssignedExtensionFieldValue<Goldilocks, 2>, Error> {
        let main_gate = self.main_gate(main_gate_config);
        let assigned_scalar = main_gate.assign_constant(ctx, scalar)?;
        let multiplied = multiplicand
            .0
            .iter()
            .map(|v| main_gate.mul(ctx, v, &assigned_scalar))
            .collect::<Result<Vec<AssignedValue<Goldilocks>>, Error>>()?;
        Ok(AssignedExtensionFieldValue(multiplied.try_into().unwrap()))
    }

    /// const_0 * multiplicand_0 * multiplicand_1 + const_1 * addend
    pub fn arithmetic_extension(
        &self,
        ctx: &mut RegionCtx<'_, Goldilocks>,
        main_gate_config: &MainGateConfig,
        const_0: Goldilocks,
        const_1: Goldilocks,
        multiplicand_0: &AssignedExtensionFieldValue<Goldilocks, 2>,
        multiplicand_1: &AssignedExtensionFieldValue<Goldilocks, 2>,
        addend: &AssignedExtensionFieldValue<Goldilocks, 2>,
    ) -> Result<AssignedExtensionFieldValue<Goldilocks, 2>, Error> {
        // multiplicand_0 * multiplicand_1
        let term_1 = self.mul(ctx, main_gate_config, multiplicand_0, multiplicand_1)?;
        // const_0 * multiplicand_0 * multiplicand_1
        let term_1 = self.scalar_mul(ctx, main_gate_config, &term_1, const_0)?;
        // const_1 * addend
        let term_2 = self.scalar_mul(ctx, main_gate_config, addend, const_1)?;
        self.add(ctx, main_gate_config, &term_1, &term_2)
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

    pub fn one_extension(
        &self,
        ctx: &mut RegionCtx<'_, Goldilocks>,
        main_gate_config: &MainGateConfig,
    ) -> Result<AssignedExtensionFieldValue<Goldilocks, 2>, Error> {
        let main_gate = self.main_gate(main_gate_config);
        let elements = [
            main_gate.assign_constant(ctx, Goldilocks::one())?,
            main_gate.assign_constant(ctx, Goldilocks::zero())?,
        ];
        Ok(AssignedExtensionFieldValue(elements))
    }

    pub fn mul_extension_with_const(
        &self,
        ctx: &mut RegionCtx<'_, Goldilocks>,
        main_gate_config: &MainGateConfig,
        const_0: Goldilocks,
        multiplicand_0: &AssignedExtensionFieldValue<Goldilocks, 2>,
        multiplicand_1: &AssignedExtensionFieldValue<Goldilocks, 2>,
    ) -> Result<AssignedExtensionFieldValue<Goldilocks, 2>, Error> {
        let zero = self.zero_extension(ctx, main_gate_config)?;
        self.arithmetic_extension(
            ctx,
            main_gate_config,
            const_0,
            Goldilocks::zero(),
            multiplicand_0,
            multiplicand_1,
            &zero,
        )
    }

    pub fn mul_extension(
        &self,
        ctx: &mut RegionCtx<'_, Goldilocks>,
        main_gate_config: &MainGateConfig,
        multiplicand_0: &AssignedExtensionFieldValue<Goldilocks, 2>,
        multiplicand_1: &AssignedExtensionFieldValue<Goldilocks, 2>,
    ) -> Result<AssignedExtensionFieldValue<Goldilocks, 2>, Error> {
        self.mul_extension_with_const(
            ctx,
            main_gate_config,
            Goldilocks::one(),
            multiplicand_0,
            multiplicand_1,
        )
    }

    pub fn mul_add_extension(
        &self,
        ctx: &mut RegionCtx<'_, Goldilocks>,
        main_gate_config: &MainGateConfig,
        a: &AssignedExtensionFieldValue<Goldilocks, 2>,
        b: &AssignedExtensionFieldValue<Goldilocks, 2>,
        c: &AssignedExtensionFieldValue<Goldilocks, 2>,
    ) -> Result<AssignedExtensionFieldValue<Goldilocks, 2>, Error> {
        let one = Goldilocks::one();
        self.arithmetic_extension(ctx, main_gate_config, one, one, a, b, c)
    }

    pub fn square_extension(
        &self,
        ctx: &mut RegionCtx<'_, Goldilocks>,
        main_gate_config: &MainGateConfig,
        x: &AssignedExtensionFieldValue<Goldilocks, 2>,
    ) -> Result<AssignedExtensionFieldValue<Goldilocks, 2>, Error> {
        self.mul_extension(ctx, main_gate_config, x, x)
    }

    pub fn exp_power_of_2_extension(
        &self,
        ctx: &mut RegionCtx<'_, Goldilocks>,
        main_gate_config: &MainGateConfig,
        mut base: AssignedExtensionFieldValue<Goldilocks, 2>,
        power_log: usize,
    ) -> Result<AssignedExtensionFieldValue<Goldilocks, 2>, Error> {
        for _ in 0..power_log {
            base = self.square_extension(ctx, main_gate_config, &base)?;
        }
        Ok(base)
    }

    pub fn mul_many_extension(
        &self,
        ctx: &mut RegionCtx<'_, Goldilocks>,
        main_gate_config: &MainGateConfig,
        terms: Vec<AssignedExtensionFieldValue<Goldilocks, 2>>,
    ) -> Result<AssignedExtensionFieldValue<Goldilocks, 2>, Error> {
        let one = self.one_extension(ctx, main_gate_config)?;
        let result = terms.into_iter().fold(one, |acc, term| {
            self.mul_extension(ctx, main_gate_config, &acc, &term)
                .unwrap()
        });
        Ok(result)
    }

    pub fn sub_extension(
        &self,
        ctx: &mut RegionCtx<'_, Goldilocks>,
        main_gate_config: &MainGateConfig,
        lhs: &AssignedExtensionFieldValue<Goldilocks, 2>,
        rhs: &AssignedExtensionFieldValue<Goldilocks, 2>,
    ) -> Result<AssignedExtensionFieldValue<Goldilocks, 2>, Error> {
        let one = Goldilocks::one();
        let one_extension = self.one_extension(ctx, main_gate_config)?;
        self.arithmetic_extension(ctx, main_gate_config, one, -one, lhs, &one_extension, rhs)
    }

    pub fn constant_extension(
        &self,
        ctx: &mut RegionCtx<'_, Goldilocks>,
        main_gate_config: &MainGateConfig,
        constant: &[Goldilocks; 2],
    ) -> Result<AssignedExtensionFieldValue<Goldilocks, 2>, Error> {
        let main_gate = self.main_gate(main_gate_config);
        let elements = constant
            .into_iter()
            .map(|c| main_gate.assign_constant(ctx, *c))
            .collect::<Result<Vec<AssignedValue<Goldilocks>>, Error>>()?;
        Ok(AssignedExtensionFieldValue(elements.try_into().unwrap()))
    }
}
