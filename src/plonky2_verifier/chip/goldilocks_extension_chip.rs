use halo2_proofs::halo2curves::ff::PrimeField;
use halo2_proofs::plonk::Error;
use halo2wrong_maingate::{fe_to_big, AssignedValue};
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::Field;
use plonky2::field::{extension::quadratic::QuadraticExtension, types::PrimeField64};

use crate::plonky2_verifier::context::RegionCtx;
use crate::plonky2_verifier::types::assigned::AssignedExtensionFieldValue;

use super::goldilocks_chip::{GoldilocksChip, GoldilocksChipConfig};
use super::native_chip::arithmetic_chip::{ArithmeticChip, TermExt};

pub struct AssignedExtensionAlgebra<F: PrimeField>(pub [AssignedExtensionFieldValue<F, 2>; 2]);

pub struct GoldilocksExtensionChip<F: PrimeField> {
    goldilocks_chip_config: GoldilocksChipConfig<F>,
}

impl<F: PrimeField> GoldilocksExtensionChip<F> {
    pub fn new(goldilocks_chip_config: &GoldilocksChipConfig<F>) -> Self {
        Self {
            goldilocks_chip_config: goldilocks_chip_config.clone(),
        }
    }

    pub fn goldilocks_chip(&self) -> GoldilocksChip<F> {
        GoldilocksChip::new(&self.goldilocks_chip_config)
    }

    pub fn arithmetic_chip(&self) -> ArithmeticChip<F> {
        self.goldilocks_chip().arithmetic_chip()
    }

    pub fn goldilocks_to_native_fe(&self, goldilocks: GoldilocksField) -> F {
        F::from(goldilocks.to_canonical_u64())
    }

    // assumes `fe` is already in goldilocks field
    fn native_fe_to_goldilocks(&self, fe: F) -> GoldilocksField {
        let fe_big = fe_to_big::<F>(fe);
        let digits = fe_big.to_u64_digits();
        if digits.len() == 0 {
            GoldilocksField::ZERO
        } else {
            GoldilocksField::from_canonical_u64(digits[0])
        }
    }
    pub fn w() -> GoldilocksField {
        GoldilocksField::from_canonical_u64(7)
    }
}

// Layouts GoldilocksField quadratic extension field arithmetic constraints
impl<F: PrimeField> GoldilocksExtensionChip<F> {
    pub fn mul_add_extension(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        a: &AssignedExtensionFieldValue<F, 2>,
        b: &AssignedExtensionFieldValue<F, 2>,
        c: &AssignedExtensionFieldValue<F, 2>,
    ) -> Result<AssignedExtensionFieldValue<F, 2>, Error> {
        let assigned = self.arithmetic_chip().apply_ext(
            ctx,
            TermExt::Assigned(&a.0),
            TermExt::Assigned(&b.0),
            TermExt::Assigned(&c.0),
        )?;
        Ok(AssignedExtensionFieldValue(assigned.r))
    }

    pub fn div_extension(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        x: &AssignedExtensionFieldValue<F, 2>,
        y: &AssignedExtensionFieldValue<F, 2>,
    ) -> Result<AssignedExtensionFieldValue<F, 2>, Error> {
        y.0[0]
            .value()
            .zip(y.0[1].value())
            .map(|(a, b)| assert!(*a != F::from(0) || *b != F::from(0)));
        let goldilocks_chip = self.goldilocks_chip();
        let y_inv = y.0[0]
            .value()
            .zip(y.0[1].value())
            .map(|(&hi, &lo)| {
                let y_inv = QuadraticExtension([
                    self.native_fe_to_goldilocks(hi),
                    self.native_fe_to_goldilocks(lo),
                ])
                .inverse()
                .0
                .map(|v| self.goldilocks_to_native_fe(v));
                (y_inv[0], y_inv[1])
            })
            .unzip();
        let y_inv0 = goldilocks_chip.assign_value(ctx, y_inv.0)?;
        let y_inv1 = goldilocks_chip.assign_value(ctx, y_inv.1)?;
        let y_inv = AssignedExtensionFieldValue([y_inv0, y_inv1]);
        // y * y_inv = 1
        let yy_inv = self.mul_extension(ctx, y, &y_inv)?;
        self.assert_one_extension(ctx, &yy_inv)?;

        let x_div_y = self.mul_extension(ctx, x, &y_inv)?;
        Ok(x_div_y)
    }

    pub fn div_add_extension(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        x: &AssignedExtensionFieldValue<F, 2>,
        y: &AssignedExtensionFieldValue<F, 2>,
        z: &AssignedExtensionFieldValue<F, 2>,
    ) -> Result<AssignedExtensionFieldValue<F, 2>, Error> {
        let x_div_y = self.div_extension(ctx, x, y)?;
        self.add_extension(ctx, &x_div_y, z)
    }

    pub fn add_extension(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        addend_0: &AssignedExtensionFieldValue<F, 2>,
        addend_1: &AssignedExtensionFieldValue<F, 2>,
    ) -> Result<AssignedExtensionFieldValue<F, 2>, Error> {
        let goldilocks_chip = self.goldilocks_chip();
        let added = addend_0
            .0
            .iter()
            .zip(addend_1.0.iter())
            .map(|(addend_0, addend_1)| goldilocks_chip.add(ctx, addend_0, addend_1))
            .collect::<Result<Vec<AssignedValue<F>>, Error>>()?;
        Ok(AssignedExtensionFieldValue(added.try_into().unwrap()))
    }

    pub fn scalar_mul(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        multiplicand: &AssignedExtensionFieldValue<F, 2>,
        scalar: GoldilocksField,
    ) -> Result<AssignedExtensionFieldValue<F, 2>, Error> {
        let goldilocks_chip = self.goldilocks_chip();
        let assigned_scalar = goldilocks_chip.assign_constant(ctx, scalar)?;
        let multiplied = multiplicand
            .0
            .iter()
            .map(|v| goldilocks_chip.mul(ctx, v, &assigned_scalar))
            .collect::<Result<Vec<AssignedValue<F>>, Error>>()?;
        Ok(AssignedExtensionFieldValue(multiplied.try_into().unwrap()))
    }

    /// const_0 * multiplicand_0 * multiplicand_1 + const_1 * addend
    pub fn arithmetic_extension(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        const_0: GoldilocksField,
        const_1: GoldilocksField,
        multiplicand_0: &AssignedExtensionFieldValue<F, 2>,
        multiplicand_1: &AssignedExtensionFieldValue<F, 2>,
        addend: &AssignedExtensionFieldValue<F, 2>,
    ) -> Result<AssignedExtensionFieldValue<F, 2>, Error> {
        // multiplicand_0 * multiplicand_1
        let mut term_1 = self.mul_extension(ctx, multiplicand_0, multiplicand_1)?;
        // const_0 * multiplicand_0 * multiplicand_1
        term_1 = self.scalar_mul(ctx, &term_1, const_0)?;
        // const_1 * addend
        let term_2 = self.scalar_mul(ctx, addend, const_1)?;
        self.add_extension(ctx, &term_1, &term_2)
    }

    pub fn zero_extension(
        &self,
        ctx: &mut RegionCtx<'_, F>,
    ) -> Result<AssignedExtensionFieldValue<F, 2>, Error> {
        let goldilocks_chip = self.goldilocks_chip();
        let elements = (0..2)
            .map(|_| goldilocks_chip.assign_constant(ctx, GoldilocksField::ZERO))
            .collect::<Result<Vec<AssignedValue<F>>, Error>>()?;
        Ok(AssignedExtensionFieldValue(elements.try_into().unwrap()))
    }

    pub fn one_extension(
        &self,
        ctx: &mut RegionCtx<'_, F>,
    ) -> Result<AssignedExtensionFieldValue<F, 2>, Error> {
        let goldilocks_chip = self.goldilocks_chip();
        let elements = [
            goldilocks_chip.assign_constant(ctx, GoldilocksField::ONE)?,
            goldilocks_chip.assign_constant(ctx, GoldilocksField::ZERO)?,
        ];
        Ok(AssignedExtensionFieldValue(elements))
    }

    pub fn two_extension(
        &self,
        ctx: &mut RegionCtx<'_, F>,
    ) -> Result<AssignedExtensionFieldValue<F, 2>, Error> {
        let goldilocks_chip = self.goldilocks_chip();
        let elements = [
            goldilocks_chip.assign_constant(ctx, GoldilocksField::from_canonical_u64(2))?,
            goldilocks_chip.assign_constant(ctx, GoldilocksField::ZERO)?,
        ];
        Ok(AssignedExtensionFieldValue(elements))
    }

    pub fn mul_extension_with_const(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        const_0: GoldilocksField,
        multiplicand_0: &AssignedExtensionFieldValue<F, 2>,
        multiplicand_1: &AssignedExtensionFieldValue<F, 2>,
    ) -> Result<AssignedExtensionFieldValue<F, 2>, Error> {
        let zero = self.zero_extension(ctx)?;
        self.arithmetic_extension(
            ctx,
            const_0,
            GoldilocksField::ZERO,
            multiplicand_0,
            multiplicand_1,
            &zero,
        )
    }

    pub fn mul_extension(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        multiplicand_0: &AssignedExtensionFieldValue<F, 2>,
        multiplicand_1: &AssignedExtensionFieldValue<F, 2>,
    ) -> Result<AssignedExtensionFieldValue<F, 2>, Error> {
        let zero = self.zero_extension(ctx)?;
        self.mul_add_extension(ctx, multiplicand_0, multiplicand_1, &zero)
    }

    pub fn mul_sub_extension(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        a: &AssignedExtensionFieldValue<F, 2>,
        b: &AssignedExtensionFieldValue<F, 2>,
        c: &AssignedExtensionFieldValue<F, 2>,
    ) -> Result<AssignedExtensionFieldValue<F, 2>, Error> {
        let one = GoldilocksField::ONE;
        self.arithmetic_extension(ctx, one, -one, a, b, c)
    }

    pub fn square_extension(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        x: &AssignedExtensionFieldValue<F, 2>,
    ) -> Result<AssignedExtensionFieldValue<F, 2>, Error> {
        self.mul_extension(ctx, x, x)
    }

    pub fn exp_power_of_2_extension(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        mut base: AssignedExtensionFieldValue<F, 2>,
        power_log: usize,
    ) -> Result<AssignedExtensionFieldValue<F, 2>, Error> {
        for _ in 0..power_log {
            base = self.square_extension(ctx, &base)?;
        }
        Ok(base)
    }

    pub fn exp(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        base: &AssignedExtensionFieldValue<F, 2>,
        power: usize,
    ) -> Result<AssignedExtensionFieldValue<F, 2>, Error> {
        match power {
            0 => return self.one_extension(ctx),
            1 => return Ok(base.clone()),
            2 => return self.square_extension(ctx, base),
            _ => (),
        }
        let mut product = self.one_extension(ctx)?;
        for _ in 0..power {
            product = self.mul_extension(ctx, &product, base)?;
        }
        Ok(product)
    }

    pub fn mul_many_extension(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        terms: Vec<AssignedExtensionFieldValue<F, 2>>,
    ) -> Result<AssignedExtensionFieldValue<F, 2>, Error> {
        let one = self.one_extension(ctx)?;
        let result = terms.into_iter().fold(one, |acc, term| {
            self.mul_extension(ctx, &acc, &term).unwrap()
        });
        Ok(result)
    }

    pub fn sub_extension(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        lhs: &AssignedExtensionFieldValue<F, 2>,
        rhs: &AssignedExtensionFieldValue<F, 2>,
    ) -> Result<AssignedExtensionFieldValue<F, 2>, Error> {
        let one = GoldilocksField::ONE;
        let one_extension = self.one_extension(ctx)?;
        self.arithmetic_extension(ctx, one, -one, lhs, &one_extension, rhs)
    }

    pub fn constant_extension(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        constant: &[GoldilocksField; 2],
    ) -> Result<AssignedExtensionFieldValue<F, 2>, Error> {
        let goldilocks_chip = self.goldilocks_chip();
        let elements = constant
            .into_iter()
            .map(|c| goldilocks_chip.assign_constant(ctx, *c))
            .collect::<Result<Vec<AssignedValue<F>>, Error>>()?;
        Ok(AssignedExtensionFieldValue(elements.try_into().unwrap()))
    }

    pub fn convert_to_extension(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        value: &AssignedValue<F>,
    ) -> Result<AssignedExtensionFieldValue<F, 2>, Error> {
        let goldilocks_chip = self.goldilocks_chip();
        Ok(AssignedExtensionFieldValue([
            value.clone(),
            goldilocks_chip.assign_constant(ctx, GoldilocksField::ZERO)?,
        ]))
    }

    pub fn reduce_extension(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        base: &AssignedExtensionFieldValue<F, 2>,
        terms: &Vec<AssignedExtensionFieldValue<F, 2>>,
    ) -> Result<AssignedExtensionFieldValue<F, 2>, Error> {
        let zero_extension = self.zero_extension(ctx)?;
        let result = terms.iter().rev().fold(zero_extension, |acc, term| {
            self.mul_add_extension(ctx, &acc, base, term).unwrap()
        });
        Ok(result)
    }

    pub fn reduce_base_field_terms_extension(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        base: &AssignedExtensionFieldValue<F, 2>,
        terms: &Vec<AssignedValue<F>>,
    ) -> Result<AssignedExtensionFieldValue<F, 2>, Error> {
        let terms = terms
            .iter()
            .map(|t| self.convert_to_extension(ctx, t))
            .collect::<Result<Vec<AssignedExtensionFieldValue<F, 2>>, Error>>()?;
        self.reduce_extension(ctx, base, &terms)
    }

    pub fn reduce_extension_field_terms_base(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        base: &AssignedValue<F>,
        terms: &Vec<AssignedExtensionFieldValue<F, 2>>,
    ) -> Result<AssignedExtensionFieldValue<F, 2>, Error> {
        let base = self.convert_to_extension(ctx, base)?;
        self.reduce_extension(ctx, &base, terms)
    }

    // shifted * factor^power
    pub fn shift(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        factor: &AssignedExtensionFieldValue<F, 2>,
        power: usize,
        shifted: &AssignedExtensionFieldValue<F, 2>,
    ) -> Result<AssignedExtensionFieldValue<F, 2>, Error> {
        let exp = self.exp(ctx, factor, power)?;
        self.mul_extension(ctx, &exp, shifted)
    }

    pub fn assert_equal_extension(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        lhs: &AssignedExtensionFieldValue<F, 2>,
        rhs: &AssignedExtensionFieldValue<F, 2>,
    ) -> Result<(), Error> {
        let goldilocks_chip = self.goldilocks_chip();
        goldilocks_chip.assert_equal(ctx, &lhs.0[0], &rhs.0[0])?;
        goldilocks_chip.assert_equal(ctx, &lhs.0[1], &rhs.0[1])?;
        Ok(())
    }

    pub fn assert_one_extension(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        a: &AssignedExtensionFieldValue<F, 2>,
    ) -> Result<(), Error> {
        let goldilocks_chip = self.goldilocks_chip();
        goldilocks_chip.assert_one(ctx, &a.0[0])?;
        goldilocks_chip.assert_zero(ctx, &a.0[1])?;
        Ok(())
    }

    /// Accepts a condition input which does not necessarily have to be
    /// binary. In this case, it computes the arithmetic generalization of `if b { x } else { y }`,
    /// i.e. `bx - (by-y)`.
    pub fn select(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        cond: &AssignedExtensionFieldValue<F, 2>,
        a: &AssignedExtensionFieldValue<F, 2>,
        b: &AssignedExtensionFieldValue<F, 2>,
    ) -> Result<AssignedExtensionFieldValue<F, 2>, Error> {
        // cond * (a - b) + b
        let a_minus_b = self.sub_extension(ctx, a, b)?;
        let one = GoldilocksField::ONE;
        self.arithmetic_extension(ctx, one, one, cond, &a_minus_b, b)
    }
}
