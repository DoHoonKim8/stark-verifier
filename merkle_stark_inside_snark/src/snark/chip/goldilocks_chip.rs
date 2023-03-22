use std::marker::PhantomData;

use halo2_proofs::{arithmetic::Field, circuit::Value, plonk::Error};
use halo2curves::{goldilocks::fp::Goldilocks, FieldExt};
use halo2wrong::RegionCtx;
use halo2wrong_maingate::{
    big_to_fe, fe_to_big, AssignedValue, CombinationOption, CombinationOptionCommon, MainGate,
    MainGateConfig, MainGateInstructions, Term,
};
use num_bigint::BigUint;
use num_integer::Integer;
use num_traits::Num;

// TODO : use range check config
#[derive(Clone, Debug)]
pub struct GoldilocksChipConfig<F: FieldExt> {
    pub main_gate_config: MainGateConfig,
    _marker: PhantomData<F>,
}

pub struct GoldilocksChip<F: FieldExt> {
    goldilocks_chip_config: GoldilocksChipConfig<F>,
}

impl<F: FieldExt> GoldilocksChip<F> {
    pub fn configure(main_gate_config: &MainGateConfig) -> GoldilocksChipConfig<F> {
        GoldilocksChipConfig {
            main_gate_config: main_gate_config.clone(),
            _marker: PhantomData,
        }
    }

    pub fn new(goldilocks_chip_config: &GoldilocksChipConfig<F>) -> Self {
        Self {
            goldilocks_chip_config: goldilocks_chip_config.clone(),
        }
    }

    fn main_gate(&self) -> MainGate<F> {
        MainGate::new(self.goldilocks_chip_config.main_gate_config.clone())
    }

    fn goldilocks_modulus(&self) -> BigUint {
        BigUint::from_str_radix(&Goldilocks::MODULUS[2..], 16).unwrap()
    }

    pub fn goldilocks_to_native_fe(&self, goldilocks: Goldilocks) -> F {
        big_to_fe::<F>(fe_to_big::<Goldilocks>(goldilocks))
    }

    pub fn assign_value(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        unassigned: Value<F>,
    ) -> Result<AssignedValue<F>, Error> {
        let main_gate = self.main_gate();
        main_gate.assign_value(ctx, unassigned)
    }

    // TODO : decompose the Goldilocks value and range check
    pub fn assign_constant(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        constant: Goldilocks,
    ) -> Result<AssignedValue<F>, Error> {
        let constant: F = big_to_fe(fe_to_big::<Goldilocks>(constant));
        self.assign_value(ctx, Value::known(constant))
    }

    pub fn add(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        lhs: &AssignedValue<F>,
        rhs: &AssignedValue<F>,
    ) -> Result<AssignedValue<F>, Error> {
        let main_gate = self.main_gate();
        let goldilocks_modulus = self.goldilocks_modulus();
        let (quotient, remainder) = lhs
            .value()
            .zip(rhs.value())
            .map(|(l, r)| {
                let (q, r) = (fe_to_big(*l) + fe_to_big(*r)).div_rem(&goldilocks_modulus);
                (big_to_fe(q), big_to_fe(r))
            })
            .unzip();
        Ok(main_gate
            .apply(
                ctx,
                [
                    Term::assigned_to_add(lhs),
                    Term::assigned_to_add(rhs),
                    Term::Unassigned(quotient, -big_to_fe::<F>(goldilocks_modulus)),
                    Term::unassigned_to_sub(remainder),
                ],
                F::zero(),
                CombinationOptionCommon::OneLinerAdd.into(),
            )?
            .swap_remove(3))
    }

    pub fn sub(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        lhs: &AssignedValue<F>,
        rhs: &AssignedValue<F>,
    ) -> Result<AssignedValue<F>, Error> {
        let main_gate = self.main_gate();
        let goldilocks_modulus = self.goldilocks_modulus();
        let (quotient, remainder) = lhs
            .value()
            .zip(rhs.value())
            .map(|(l, r)| {
                let (q, r) = (fe_to_big(*l) + goldilocks_modulus.clone() - fe_to_big(*r))
                    .div_rem(&goldilocks_modulus.clone());
                (big_to_fe(q), big_to_fe(r))
            })
            .unzip();
        Ok(main_gate
            .apply(
                ctx,
                [
                    Term::assigned_to_add(lhs),
                    Term::unassigned_to_add(Value::known(big_to_fe(goldilocks_modulus.clone()))),
                    Term::assigned_to_sub(rhs),
                    Term::Unassigned(quotient, -big_to_fe::<F>(goldilocks_modulus.clone())),
                    Term::unassigned_to_sub(remainder),
                ],
                F::zero(),
                CombinationOptionCommon::OneLinerAdd.into(),
            )?
            .swap_remove(4))
    }

    // TODO : range check
    pub fn mul(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        lhs: &AssignedValue<F>,
        rhs: &AssignedValue<F>,
    ) -> Result<AssignedValue<F>, Error> {
        self.mul_with_constant(ctx, lhs, rhs, Goldilocks::one())
    }

    /// Assigns a new witness `r` as:
    /// `lhs * rhs * constant - p * q - r = 0`
    pub fn mul_with_constant(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        lhs: &AssignedValue<F>,
        rhs: &AssignedValue<F>,
        constant: Goldilocks,
    ) -> Result<AssignedValue<F>, Error> {
        let main_gate = self.main_gate();
        let goldilocks_modulus = self.goldilocks_modulus();
        let constant = self.goldilocks_to_native_fe(constant);
        let (quotient, remainder) = lhs
            .value()
            .zip(rhs.value())
            .map(|(l, r)| {
                let (q, r) = (fe_to_big(*l) * fe_to_big(*r) * fe_to_big(constant))
                    .div_rem(&goldilocks_modulus);
                (big_to_fe(q), big_to_fe(r))
            })
            .unzip();
        Ok(main_gate
            .apply(
                ctx,
                [
                    Term::assigned_to_mul(lhs),
                    Term::assigned_to_mul(rhs),
                    Term::Unassigned(quotient, -big_to_fe::<F>(goldilocks_modulus)),
                    Term::unassigned_to_sub(remainder),
                ],
                F::zero(),
                CombinationOptionCommon::CombineToNextScaleMul(F::zero(), constant).into(),
            )?
            .swap_remove(3))
    }

    pub fn mul_add_constant(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        a: &AssignedValue<F>,
        b: &AssignedValue<F>,
        to_add: Goldilocks,
    ) -> Result<AssignedValue<F>, Error> {
        let main_gate = self.main_gate();
        let goldilocks_modulus = self.goldilocks_modulus();
        let to_add = self.goldilocks_to_native_fe(to_add);
        let (quotient, remainder) = a
            .value()
            .zip(b.value())
            .map(|(l, r)| {
                let (q, r) = (fe_to_big(*l) * fe_to_big(*r) + fe_to_big(to_add))
                    .div_rem(&goldilocks_modulus);
                (big_to_fe(q), big_to_fe(r))
            })
            .unzip();
        Ok(main_gate
            .apply(
                ctx,
                [
                    Term::assigned_to_mul(a),
                    Term::assigned_to_mul(b),
                    Term::unassigned_to_add(Value::known(to_add)),
                    Term::Unassigned(quotient, -big_to_fe::<F>(goldilocks_modulus)),
                    Term::unassigned_to_sub(remainder),
                ],
                F::zero(),
                CombinationOptionCommon::OneLinerMul.into(),
            )?
            .swap_remove(4))
    }

    pub fn add_constant(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        a: &AssignedValue<F>,
        constant: Goldilocks,
    ) -> Result<AssignedValue<F>, Error> {
        let main_gate = self.main_gate();
        let goldilocks_modulus = self.goldilocks_modulus();
        let (quotient, remainder) = a
            .value()
            .zip(Value::known(self.goldilocks_to_native_fe(constant)))
            .map(|(l, r)| {
                let (q, r) = (fe_to_big(*l) + fe_to_big(r)).div_rem(&goldilocks_modulus);
                (big_to_fe(q), big_to_fe(r))
            })
            .unzip();
        Ok(main_gate
            .apply(
                ctx,
                [
                    Term::assigned_to_add(a),
                    Term::unassigned_to_add(Value::known(self.goldilocks_to_native_fe(constant))),
                    Term::Unassigned(quotient, -big_to_fe::<F>(goldilocks_modulus)),
                    Term::unassigned_to_sub(remainder),
                ],
                F::zero(),
                CombinationOptionCommon::OneLinerAdd.into(),
            )?
            .swap_remove(3))
    }

    pub fn assert_equal(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        lhs: &AssignedValue<F>,
        rhs: &AssignedValue<F>,
    ) -> Result<(), Error> {
        let main_gate = self.main_gate();
        let lhs_minus_rhs = self.sub(ctx, lhs, rhs)?;
        main_gate.assert_zero(ctx, &lhs_minus_rhs)
    }

    pub fn assert_one(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        a: &AssignedValue<F>,
    ) -> Result<(), Error> {
        let one = self.assign_constant(ctx, Goldilocks::one())?;
        self.assert_equal(ctx, a, &one)
    }

    pub fn assert_zero(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        a: &AssignedValue<F>,
    ) -> Result<(), Error> {
        let zero = self.assign_constant(ctx, Goldilocks::zero())?;
        self.assert_equal(ctx, a, &zero)
    }

    pub fn compose(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        terms: &[Term<F>],
        constant: Goldilocks,
    ) -> Result<AssignedValue<F>, Error> {
        assert!(!terms.is_empty(), "At least one term is expected");
        let goldilocks_modulus = self.goldilocks_modulus();
        let composed = terms.iter().fold(
            Value::known(self.goldilocks_to_native_fe(constant)),
            |acc, term| {
                acc.zip(term.coeff()).map(|(acc, coeff)| {
                    let (_, remainder) = (fe_to_big(acc)
                        + fe_to_big(coeff) * fe_to_big(term.base()))
                    .div_rem(&goldilocks_modulus);
                    big_to_fe(remainder)
                })
            },
        );
        let composed = self.assign_value(ctx, composed)?;
        Ok(composed)
    }
}
