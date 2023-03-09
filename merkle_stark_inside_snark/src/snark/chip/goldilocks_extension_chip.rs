use halo2_proofs::arithmetic::Field;
use halo2_proofs::circuit::Value;
use halo2_proofs::plonk::Error;
use halo2curves::goldilocks::fp::Goldilocks;
use halo2curves::goldilocks::fp2::QuadraticExtension;
use halo2wrong::RegionCtx;
use halo2wrong_maingate::{
    AssignedValue, CombinationOption, MainGate, MainGateConfig, MainGateInstructions, Term,
};

use crate::snark::types::assigned::AssignedExtensionFieldValue;

pub struct GoldilocksExtensionChip {
    main_gate_config: MainGateConfig,
}

impl GoldilocksExtensionChip {
    pub fn new(main_gate_config: &MainGateConfig) -> Self {
        Self {
            main_gate_config: main_gate_config.clone(),
        }
    }

    pub fn main_gate(&self) -> MainGate<Goldilocks> {
        MainGate::<Goldilocks>::new(self.main_gate_config.clone())
    }
}

// Layouts Goldilocks quadratic extension field arithmetic constraints
impl GoldilocksExtensionChip {
    // lhs[0] * rhs[0] + w * lhs[1] * rhs[1] - res[0] = 0
    // lhs[0] * rhs[1] + lhs[1] * rhs[0] - res[1] = 0

    // Witness layout:
    // | A      | B      | C      | D      | E      |
    // | ---    | ---    | -      | ---    | ---    |
    // | lhs[0] | rhs[0] | lhs[1] | rhs[1] | res[0] |
    // | lhs[0] | rhs[1] | lhs[1] | rhs[0] | res[1] |
    pub fn mul(
        &self,
        ctx: &mut RegionCtx<'_, Goldilocks>,
        lhs: &AssignedExtensionFieldValue<Goldilocks, 2>,
        rhs: &AssignedExtensionFieldValue<Goldilocks, 2>,
    ) -> Result<AssignedExtensionFieldValue<Goldilocks, 2>, Error> {
        let main_gate = self.main_gate();
        let zero = Goldilocks::zero();
        let one = Goldilocks::one();
        let w = Goldilocks::from(7);
        let mut res = [Value::unknown(); 2];
        res[0] = lhs.0[0].value().zip(rhs.0[0].value()).map(|(l, r)| *l * *r)
            + lhs.0[1]
                .value()
                .zip(rhs.0[1].value())
                .map(|(l, r)| w * *l * *r);
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

    // Witness layout:
    // | A    | B        | C    | D        | E      |
    // | ---  | ---      | -    | ---      | ---    |
    // | y[0] | y_inv[0] | y[1] | y_inv[1] |        |
    // | y[0| | y_inv[1] | y[1| | y_inv[0] |        |
    // | x[0| | y_inv[0] | x[1| | y_inv[1] | res[0] |
    // | x[0| | y_inv[1] | x[1| | y_inv[0] | res[1] |
    pub fn div_add_extension(
        &self,
        ctx: &mut RegionCtx<'_, Goldilocks>,
        x: &AssignedExtensionFieldValue<Goldilocks, 2>,
        y: &AssignedExtensionFieldValue<Goldilocks, 2>,
        z: &AssignedExtensionFieldValue<Goldilocks, 2>,
    ) -> Result<AssignedExtensionFieldValue<Goldilocks, 2>, Error> {
        let main_gate = self.main_gate();
        let zero = Goldilocks::zero();
        let one = Goldilocks::one();
        let w = Goldilocks::from(7);

        let y_inv = y.0[0]
            .value()
            .zip(y.0[1].value())
            .map(|(&hi, &lo)| {
                let y_inv = QuadraticExtension([hi, lo]).invert().unwrap().0;
                (y_inv[0], y_inv[1])
            })
            .unzip();
        let mut res = [Value::unknown(); 2];
        res[0] = x.0[0].value().zip(y_inv.0).map(|(l, r)| *l * r)
            + x.0[1].value().zip(y_inv.1).map(|(l, r)| w * *l * r);
        res[1] = x.0[0].value().zip(y_inv.1).map(|(l, r)| *l * r)
            + x.0[1].value().zip(y_inv.0).map(|(l, r)| *l * r);

        // y[0] * y_inv[0] + w * y[1] * y_inv[1] - 1 = 0
        main_gate.apply(
            ctx,
            [
                Term::assigned_to_mul(&y.0[0]),
                Term::unassigned_to_mul(y_inv.0),
                Term::assigned_to_mul(&y.0[1]),
                Term::unassigned_to_mul(y_inv.1),
            ],
            -one,
            CombinationOption::OneLinerDoubleMul(w),
        )?;

        // y[0] * y_inv[1] + y[1] * y_inv[0] = 0
        main_gate.apply(
            ctx,
            [
                Term::assigned_to_mul(&y.0[0]),
                Term::unassigned_to_mul(y_inv.1),
                Term::assigned_to_mul(&y.0[1]),
                Term::unassigned_to_mul(y_inv.0),
            ],
            zero,
            CombinationOption::OneLinerDoubleMul(one),
        )?;

        // x[0] * y_inv[0] + w * x[1] * y_inv[1] - res[0] = 0
        let mut assigned_1 = main_gate.apply(
            ctx,
            [
                Term::assigned_to_mul(&x.0[0]),
                Term::unassigned_to_mul(y_inv.0),
                Term::assigned_to_mul(&x.0[1]),
                Term::unassigned_to_mul(y_inv.1),
                Term::unassigned_to_sub(res[0]),
            ],
            zero,
            CombinationOption::OneLinerDoubleMul(w),
        )?;

        // x[0] * y_inv[1] + x[1] * y_inv[0] - res[1] = 0
        let mut assigned_2 = main_gate.apply(
            ctx,
            [
                Term::assigned_to_mul(&x.0[0]),
                Term::unassigned_to_mul(y_inv.1),
                Term::assigned_to_mul(&x.0[1]),
                Term::unassigned_to_mul(y_inv.0),
                Term::unassigned_to_sub(res[1]),
            ],
            zero,
            CombinationOption::OneLinerDoubleMul(one),
        )?;
        let res =
            AssignedExtensionFieldValue([assigned_1.swap_remove(4), assigned_2.swap_remove(4)]);
        Ok(res)
    }

    pub fn div_extension(
        &self,
        ctx: &mut RegionCtx<'_, Goldilocks>,
        x: &AssignedExtensionFieldValue<Goldilocks, 2>,
        y: &AssignedExtensionFieldValue<Goldilocks, 2>,
    ) -> Result<AssignedExtensionFieldValue<Goldilocks, 2>, Error> {
        let zero = self.zero_extension(ctx)?;
        self.div_add_extension(ctx, x, y, &zero)
    }

    pub fn add_extension(
        &self,
        ctx: &mut RegionCtx<'_, Goldilocks>,
        addend_0: &AssignedExtensionFieldValue<Goldilocks, 2>,
        addend_1: &AssignedExtensionFieldValue<Goldilocks, 2>,
    ) -> Result<AssignedExtensionFieldValue<Goldilocks, 2>, Error> {
        let main_gate = self.main_gate();
        let added = addend_0
            .0
            .iter()
            .zip(addend_1.0.iter())
            .map(|(addend_0, addend_1)| main_gate.add(ctx, addend_0, addend_1))
            .collect::<Result<Vec<AssignedValue<Goldilocks>>, Error>>()?;
        Ok(AssignedExtensionFieldValue(added.try_into().unwrap()))
    }

    pub fn scalar_mul(
        &self,
        ctx: &mut RegionCtx<'_, Goldilocks>,
        multiplicand: &AssignedExtensionFieldValue<Goldilocks, 2>,
        scalar: Goldilocks,
    ) -> Result<AssignedExtensionFieldValue<Goldilocks, 2>, Error> {
        let main_gate = self.main_gate();
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
        const_0: Goldilocks,
        const_1: Goldilocks,
        multiplicand_0: &AssignedExtensionFieldValue<Goldilocks, 2>,
        multiplicand_1: &AssignedExtensionFieldValue<Goldilocks, 2>,
        addend: &AssignedExtensionFieldValue<Goldilocks, 2>,
    ) -> Result<AssignedExtensionFieldValue<Goldilocks, 2>, Error> {
        // multiplicand_0 * multiplicand_1
        let mut term_1 = self.mul(ctx, multiplicand_0, multiplicand_1)?;
        // const_0 * multiplicand_0 * multiplicand_1
        term_1 = self.scalar_mul(ctx, &term_1, const_0)?;
        // const_1 * addend
        let term_2 = self.scalar_mul(ctx, addend, const_1)?;
        self.add_extension(ctx, &term_1, &term_2)
    }

    pub fn zero_extension(
        &self,
        ctx: &mut RegionCtx<'_, Goldilocks>,
    ) -> Result<AssignedExtensionFieldValue<Goldilocks, 2>, Error> {
        let main_gate = self.main_gate();
        let elements = (0..2)
            .map(|i| main_gate.assign_constant(ctx, Goldilocks::zero()))
            .collect::<Result<Vec<AssignedValue<Goldilocks>>, Error>>()?;
        Ok(AssignedExtensionFieldValue(elements.try_into().unwrap()))
    }

    pub fn one_extension(
        &self,
        ctx: &mut RegionCtx<'_, Goldilocks>,
    ) -> Result<AssignedExtensionFieldValue<Goldilocks, 2>, Error> {
        let main_gate = self.main_gate();
        let elements = [
            main_gate.assign_constant(ctx, Goldilocks::one())?,
            main_gate.assign_constant(ctx, Goldilocks::zero())?,
        ];
        Ok(AssignedExtensionFieldValue(elements))
    }

    pub fn mul_extension_with_const(
        &self,
        ctx: &mut RegionCtx<'_, Goldilocks>,
        const_0: Goldilocks,
        multiplicand_0: &AssignedExtensionFieldValue<Goldilocks, 2>,
        multiplicand_1: &AssignedExtensionFieldValue<Goldilocks, 2>,
    ) -> Result<AssignedExtensionFieldValue<Goldilocks, 2>, Error> {
        let zero = self.zero_extension(ctx)?;
        self.arithmetic_extension(
            ctx,
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
        multiplicand_0: &AssignedExtensionFieldValue<Goldilocks, 2>,
        multiplicand_1: &AssignedExtensionFieldValue<Goldilocks, 2>,
    ) -> Result<AssignedExtensionFieldValue<Goldilocks, 2>, Error> {
        self.mul_extension_with_const(ctx, Goldilocks::one(), multiplicand_0, multiplicand_1)
    }

    pub fn mul_add_extension(
        &self,
        ctx: &mut RegionCtx<'_, Goldilocks>,
        a: &AssignedExtensionFieldValue<Goldilocks, 2>,
        b: &AssignedExtensionFieldValue<Goldilocks, 2>,
        c: &AssignedExtensionFieldValue<Goldilocks, 2>,
    ) -> Result<AssignedExtensionFieldValue<Goldilocks, 2>, Error> {
        let one = Goldilocks::one();
        self.arithmetic_extension(ctx, one, one, a, b, c)
    }

    pub fn mul_sub_extension(
        &self,
        ctx: &mut RegionCtx<'_, Goldilocks>,
        a: &AssignedExtensionFieldValue<Goldilocks, 2>,
        b: &AssignedExtensionFieldValue<Goldilocks, 2>,
        c: &AssignedExtensionFieldValue<Goldilocks, 2>,
    ) -> Result<AssignedExtensionFieldValue<Goldilocks, 2>, Error> {
        let one = Goldilocks::one();
        self.arithmetic_extension(ctx, one, -one, a, b, c)
    }

    pub fn square_extension(
        &self,
        ctx: &mut RegionCtx<'_, Goldilocks>,
        x: &AssignedExtensionFieldValue<Goldilocks, 2>,
    ) -> Result<AssignedExtensionFieldValue<Goldilocks, 2>, Error> {
        self.mul_extension(ctx, x, x)
    }

    pub fn exp_power_of_2_extension(
        &self,
        ctx: &mut RegionCtx<'_, Goldilocks>,
        mut base: AssignedExtensionFieldValue<Goldilocks, 2>,
        power_log: usize,
    ) -> Result<AssignedExtensionFieldValue<Goldilocks, 2>, Error> {
        for _ in 0..power_log {
            base = self.square_extension(ctx, &base)?;
        }
        Ok(base)
    }

    pub fn mul_many_extension(
        &self,
        ctx: &mut RegionCtx<'_, Goldilocks>,
        terms: Vec<AssignedExtensionFieldValue<Goldilocks, 2>>,
    ) -> Result<AssignedExtensionFieldValue<Goldilocks, 2>, Error> {
        let one = self.one_extension(ctx)?;
        let result = terms.into_iter().fold(one, |acc, term| {
            self.mul_extension(ctx, &acc, &term).unwrap()
        });
        Ok(result)
    }

    pub fn sub_extension(
        &self,
        ctx: &mut RegionCtx<'_, Goldilocks>,
        lhs: &AssignedExtensionFieldValue<Goldilocks, 2>,
        rhs: &AssignedExtensionFieldValue<Goldilocks, 2>,
    ) -> Result<AssignedExtensionFieldValue<Goldilocks, 2>, Error> {
        let one = Goldilocks::one();
        let one_extension = self.one_extension(ctx)?;
        self.arithmetic_extension(ctx, one, -one, lhs, &one_extension, rhs)
    }

    pub fn constant_extension(
        &self,
        ctx: &mut RegionCtx<'_, Goldilocks>,
        constant: &[Goldilocks; 2],
    ) -> Result<AssignedExtensionFieldValue<Goldilocks, 2>, Error> {
        let main_gate = self.main_gate();
        let elements = constant
            .into_iter()
            .map(|c| main_gate.assign_constant(ctx, *c))
            .collect::<Result<Vec<AssignedValue<Goldilocks>>, Error>>()?;
        Ok(AssignedExtensionFieldValue(elements.try_into().unwrap()))
    }

    pub fn convert_to_extension(
        &self,
        ctx: &mut RegionCtx<'_, Goldilocks>,
        value: &AssignedValue<Goldilocks>,
    ) -> Result<AssignedExtensionFieldValue<Goldilocks, 2>, Error> {
        let main_gate = self.main_gate();
        Ok(AssignedExtensionFieldValue([
            value.clone(),
            main_gate.assign_constant(ctx, Goldilocks::zero())?,
        ]))
    }

    pub fn reduce_arithmetic(
        &self,
        ctx: &mut RegionCtx<'_, Goldilocks>,
        base: &AssignedExtensionFieldValue<Goldilocks, 2>,
        terms: &Vec<AssignedExtensionFieldValue<Goldilocks, 2>>,
    ) -> Result<AssignedExtensionFieldValue<Goldilocks, 2>, Error> {
        let zero_extension = self.zero_extension(ctx)?;
        let result = terms.iter().rev().fold(zero_extension, |acc, term| {
            self.mul_add_extension(ctx, &acc, base, term).unwrap()
        });
        Ok(result)
    }

    pub fn assert_equal_extension(
        &self,
        ctx: &mut RegionCtx<'_, Goldilocks>,
        lhs: &AssignedExtensionFieldValue<Goldilocks, 2>,
        rhs: &AssignedExtensionFieldValue<Goldilocks, 2>,
    ) -> Result<(), Error> {
        let main_gate = self.main_gate();
        main_gate.assert_equal(ctx, &lhs.0[0], &rhs.0[0])?;
        main_gate.assert_equal(ctx, &lhs.0[1], &rhs.0[1])?;
        Ok(())
    }
}
