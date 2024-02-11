use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Value},
    halo2curves::ff::PrimeField,
    plonk::Error,
};
use halo2wrong_maingate::{fe_to_big, AssignedCondition, AssignedValue};

use halo2wrong_maingate::Term as MainGateTerm;
use plonky2::field::{
    goldilocks_field::GoldilocksField,
    types::{Field, PrimeField64},
};

use crate::snark::context::RegionCtx;

use super::native_chip::{
    all_chip::{AllChip, AllChipConfig},
    arithmetic_chip::{ArithmeticChip, Term},
    utils::goldilocks_to_fe,
};

#[derive(Clone, Debug)]
pub struct GoldilocksChipConfig<F: PrimeField> {
    all_chip_config: AllChipConfig<F>,
}

pub struct GoldilocksChip<F: PrimeField> {
    goldilocks_chip_config: GoldilocksChipConfig<F>,
}

impl<F: PrimeField> GoldilocksChip<F> {
    pub fn configure(all_chip_config: &AllChipConfig<F>) -> GoldilocksChipConfig<F> {
        GoldilocksChipConfig {
            all_chip_config: all_chip_config.clone(),
        }
    }

    pub fn new(goldilocks_chip_config: &GoldilocksChipConfig<F>) -> Self {
        Self {
            goldilocks_chip_config: goldilocks_chip_config.clone(),
        }
    }

    pub fn arithmetic_chip(&self) -> ArithmeticChip<F> {
        ArithmeticChip::new(
            &self
                .goldilocks_chip_config
                .all_chip_config
                .arithmetic_config,
        )
    }

    pub fn all_chip(&self) -> AllChip<F> {
        AllChip::new(&self.goldilocks_chip_config.all_chip_config)
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

    pub fn assign_value(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        unassigned: Value<F>,
    ) -> Result<AssignedValue<F>, Error> {
        self.arithmetic_chip().assign_value(ctx, unassigned)
    }

    pub fn assign_constant(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        constant: GoldilocksField,
    ) -> Result<AssignedValue<F>, Error> {
        self.arithmetic_chip()
            .assign_constant(ctx, goldilocks_to_fe(constant))
    }

    pub fn compose(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        terms: &[MainGateTerm<F>],
        constant: GoldilocksField,
    ) -> Result<AssignedValue<F>, Error> {
        let mut acc = self.assign_constant(ctx, constant)?;
        for term in terms {
            match term {
                MainGateTerm::Assigned(coeff, base) => {
                    acc =
                        self.mul_const_add(ctx, *coeff, self.native_fe_to_goldilocks(*base), &acc)?;
                }
                MainGateTerm::Unassigned(_, _) => panic!("unexpected"),
                MainGateTerm::Zero => panic!("unexpected"),
            }
        }
        Ok(acc)
    }

    pub fn add(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        lhs: &AssignedValue<F>,
        rhs: &AssignedValue<F>,
    ) -> Result<AssignedValue<F>, Error> {
        let one = self.assign_constant(ctx, GoldilocksField::ONE)?;
        let assigned = self.arithmetic_chip().apply(
            ctx,
            Term::Assigned(lhs),
            Term::Assigned(&one),
            Term::Assigned(rhs),
        )?;
        Ok(assigned.r)
    }

    pub fn sub(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        lhs: &AssignedValue<F>,
        rhs: &AssignedValue<F>,
    ) -> Result<AssignedValue<F>, Error> {
        let neg_one = self.assign_constant(ctx, -GoldilocksField::ONE)?;
        let assigned = self.arithmetic_chip().apply(
            ctx,
            Term::Assigned(rhs),
            Term::Assigned(&neg_one),
            Term::Assigned(lhs),
        )?;
        Ok(assigned.r)
    }

    pub fn mul(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        lhs: &AssignedValue<F>,
        rhs: &AssignedValue<F>,
    ) -> Result<AssignedValue<F>, Error> {
        self.mul_add_constant(ctx, lhs, rhs, GoldilocksField::ZERO)
    }
    /// `lhs * rhs * constant`
    pub fn mul_with_constant(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        lhs: &AssignedValue<F>,
        rhs: &AssignedValue<F>,
        constant: GoldilocksField,
    ) -> Result<AssignedValue<F>, Error> {
        let constant = self.assign_constant(ctx, constant)?;
        let lhs_rhs = self.mul(ctx, lhs, rhs)?;
        self.mul(ctx, &lhs_rhs, &constant)
    }

    pub fn mul_add_constant(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        a: &AssignedValue<F>,
        b: &AssignedValue<F>,
        to_add: GoldilocksField,
    ) -> Result<AssignedValue<F>, Error> {
        let to_add = self.assign_constant(ctx, to_add)?;
        let assigned = self.arithmetic_chip().apply(
            ctx,
            Term::Assigned(a),
            Term::Assigned(b),
            Term::Assigned(&to_add),
        )?;
        Ok(assigned.r)
    }

    pub fn mul_add(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        a: &AssignedValue<F>,
        b: &AssignedValue<F>,
        c: &AssignedValue<F>,
    ) -> Result<AssignedValue<F>, Error> {
        let assigned = self.arithmetic_chip().apply(
            ctx,
            Term::Assigned(a),
            Term::Assigned(b),
            Term::Assigned(c),
        )?;
        Ok(assigned.r)
    }

    fn mul_const_add(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        a: &AssignedValue<F>,
        constant: GoldilocksField,
        b: &AssignedValue<F>,
    ) -> Result<AssignedValue<F>, Error> {
        let constant = self.assign_constant(ctx, constant)?;
        let assigned = self.arithmetic_chip().apply(
            ctx,
            Term::Assigned(a),
            Term::Assigned(&constant),
            Term::Assigned(b),
        )?;
        Ok(assigned.r)
    }

    pub fn add_constant(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        a: &AssignedValue<F>,
        constant: GoldilocksField,
    ) -> Result<AssignedValue<F>, Error> {
        let one = self.assign_constant(ctx, GoldilocksField::ONE)?;
        self.mul_add_constant(ctx, a, &one, constant)
    }

    pub fn assert_equal(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        lhs: &AssignedValue<F>,
        rhs: &AssignedValue<F>,
    ) -> Result<(), Error> {
        self.arithmetic_chip().assert_equal(ctx, lhs, rhs)
    }

    pub fn assert_one(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        a: &AssignedValue<F>,
    ) -> Result<(), Error> {
        let one = self.assign_constant(ctx, GoldilocksField::ONE)?;
        self.assert_equal(ctx, a, &one)
    }

    pub fn assert_zero(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        a: &AssignedValue<F>,
    ) -> Result<(), Error> {
        let zero = self.assign_constant(ctx, GoldilocksField::ZERO)?;
        self.assert_equal(ctx, a, &zero)
    }

    fn assign_bit(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        bit: &Value<F>,
    ) -> Result<AssignedValue<F>, Error> {
        let one = self.assign_constant(ctx, GoldilocksField::ONE)?;
        let zero = self.assign_constant(ctx, GoldilocksField::ZERO)?;
        let neg_one = self.assign_constant(ctx, -GoldilocksField::ONE)?;
        let assigned = self.arithmetic_chip().apply(
            ctx,
            Term::Unassigned(bit.clone()),
            Term::Assigned(&one),
            Term::Assigned(&neg_one),
        )?;
        let b = assigned.a;
        let b_minus_one = assigned.r;
        let should_zero = self.mul(ctx, &b, &b_minus_one)?;
        self.assert_equal(ctx, &should_zero, &zero)?;
        Ok(b)
    }

    pub fn select(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        a: &AssignedValue<F>,
        b: &AssignedValue<F>,
        cond: &AssignedCondition<F>,
    ) -> Result<AssignedValue<F>, Error> {
        // a * cond + b * (1- cond) = (a -b) * cond + b
        let a_minus_b = self.sub(ctx, a, b)?;
        self.mul_add(ctx, &a_minus_b, cond, b)
    }

    // 4 rows
    pub fn is_zero(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        a: &AssignedValue<F>,
    ) -> Result<AssignedCondition<F>, Error> {
        let zero = self.assign_constant(ctx, GoldilocksField::ZERO)?;
        let a_inv = a.value().map(|a| {
            let a = self.native_fe_to_goldilocks(*a);
            if a == GoldilocksField::ZERO {
                F::from(0)
            } else {
                goldilocks_to_fe(a.inverse())
            }
        });
        let assigned = self.arithmetic_chip().apply(
            ctx,
            Term::Assigned(a),
            Term::Unassigned(a_inv),
            Term::Assigned(&zero),
        )?;
        let a_a_inv = assigned.r;
        let zero = assigned.c;
        let one = self.assign_constant(ctx, GoldilocksField::ONE)?;
        let out = self.sub(ctx, &one, &a_a_inv)?;
        let out_a = self.mul(ctx, &out, &a)?;
        self.assert_equal(ctx, &out_a, &zero)?;
        Ok(out)
    }

    /// Assigns array values of bit values which is equal to decomposition of
    /// given assigned value
    pub fn to_bits(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        composed: &AssignedValue<F>,
        number_of_bits: usize,
    ) -> Result<Vec<AssignedCondition<F>>, Error> {
        let zero = self.assign_constant(ctx, GoldilocksField::ZERO)?;
        let bit_value = composed
            .value()
            .map(|x| {
                let x = self.native_fe_to_goldilocks(*x).to_canonical_u64();
                let mut bits = Vec::new();
                for i in 0..64 {
                    let bit = F::from((x >> i) & 1);
                    bits.push(bit);
                }
                bits
            })
            .transpose_vec(64);
        let bit_assigned = bit_value
            .iter()
            .map(|bit| self.assign_bit(ctx, bit))
            .collect::<Result<Vec<_>, Error>>()?;

        let acc = bit_assigned.iter().enumerate().fold(
            Ok(zero),
            |acc: Result<AssignedCell<F, F>, Error>, (i, bit)| {
                let acc = acc?;
                let c = self.assign_constant(ctx, GoldilocksField::from_canonical_u64(1 << i))?;
                let assigned = self.arithmetic_chip().apply(
                    ctx,
                    Term::Assigned(bit),
                    Term::Assigned(&c),
                    Term::Assigned(&acc),
                )?;
                Ok(assigned.r)
            },
        )?;
        self.assert_equal(ctx, &acc, composed)?;
        Ok(bit_assigned[0..number_of_bits].to_vec())
    }

    pub fn from_bits(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        bits: &Vec<AssignedValue<F>>,
    ) -> Result<AssignedValue<F>, Error> {
        let zero = self.assign_constant(ctx, GoldilocksField::ZERO)?;
        let acc = bits.iter().enumerate().fold(
            Ok(zero),
            |acc: Result<AssignedCell<F, F>, Error>, (i, bit)| {
                let acc = acc?;
                let c = self.assign_constant(ctx, GoldilocksField::from_canonical_u64(1 << i))?;
                let assigned = self.arithmetic_chip().apply(
                    ctx,
                    Term::Assigned(bit),
                    Term::Assigned(&c),
                    Term::Assigned(&acc),
                )?;
                Ok(assigned.r)
            },
        )?;
        Ok(acc)
    }

    pub fn exp_power_of_2(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        a: &AssignedValue<F>,
        power_log: usize,
    ) -> Result<AssignedValue<F>, Error> {
        let mut result = a.clone();
        for _ in 0..power_log {
            result = self.mul(ctx, &result, &result)?;
        }
        Ok(result)
    }

    pub fn exp_from_bits(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        base: GoldilocksField,
        power_bits: &[AssignedValue<F>],
    ) -> Result<AssignedValue<F>, Error> {
        let mut x = self.assign_constant(ctx, GoldilocksField::ONE)?;
        let one = self.assign_constant(ctx, GoldilocksField::ONE)?;
        for (i, bit) in power_bits.iter().enumerate() {
            let is_zero_bit = self.is_zero(ctx, bit)?;
            let power = u64::from(1u64 << i).to_le();
            let base = self.assign_constant(ctx, base.exp_u64(power))?;
            let multiplicand = self.select(ctx, &one, &base, &is_zero_bit)?;
            x = self.mul(ctx, &x, &multiplicand)?;
        }
        Ok(x)
    }

    pub fn is_equal(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        a: &AssignedValue<F>,
        b: &AssignedValue<F>,
    ) -> Result<AssignedCondition<F>, Error> {
        let a_mimus_b = self.sub(ctx, a, b)?;
        self.is_zero(ctx, &a_mimus_b)
    }

    pub fn load_table(
        &self,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), halo2_proofs::plonk::Error> {
        self.arithmetic_chip().load_table(layouter)
    }
}

#[cfg(test)]
mod tests {
    use halo2_proofs::{
        circuit::{floor_planner::V1, Layouter},
        dev::MockProver,
        halo2curves::bn256::Fr,
        plonk::{Circuit, ConstraintSystem, Error},
    };
    use plonky2::field::{goldilocks_field::GoldilocksField, types::Field};

    use crate::snark::{
        chip::native_chip::{all_chip::AllChipConfig, arithmetic_chip::GOLDILOCKS_MODULUS},
        context::RegionCtx,
    };

    use super::{GoldilocksChip, GoldilocksChipConfig};

    #[derive(Clone, Default)]
    pub struct TestCircuit;

    impl Circuit<Fr> for TestCircuit {
        type Config = GoldilocksChipConfig<Fr>;

        type FloorPlanner = V1;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
            let all_chip_config = AllChipConfig::configure(meta);
            GoldilocksChipConfig { all_chip_config }
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fr>,
        ) -> Result<(), Error> {
            let chip = GoldilocksChip::new(&config);
            layouter.assign_region(
                || "mod contract",
                |region| {
                    let ctx = &mut RegionCtx::new(region, 0);

                    let a = chip.assign_constant(
                        ctx,
                        GoldilocksField::from_canonical_u64(GOLDILOCKS_MODULUS - 2),
                    )?;
                    let b = chip.assign_constant(ctx, GoldilocksField::from_canonical_u64(3))?;
                    let _c = chip.add(ctx, &a, &b)?;

                    // let a_bits = chip.to_bits(ctx, &a, 64)?;
                    // let a_recovered = chip.from_bits(ctx, &a_bits)?;

                    // chip.assert_equal(ctx, &a, &a_recovered)?;

                    // let cond = chip.assign_constant(ctx, GoldilocksField::ONE)?;

                    // let selected = chip.select(ctx, &a, &b, &cond)?;
                    // chip.assert_equal(ctx, &selected, &a)?;

                    // let should_zero = chip.is_zero(ctx, &a)?;
                    // let zero = chip.assign_constant(ctx, GoldilocksField::ZERO)?;
                    // let should_one = chip.is_zero(ctx, &zero)?;
                    // let one = chip.assign_constant(ctx, GoldilocksField::ONE)?;

                    // chip.assert_equal(ctx, &should_zero, &zero)?;
                    // chip.assert_equal(ctx, &should_one, &one)?;

                    Ok(())
                },
            )?;
            chip.load_table(&mut layouter)?;
            Ok(())
        }
    }

    const DEGREE: u32 = 17;

    #[test]
    fn test_goldilocks_chip() {
        let circuit = TestCircuit;
        let instance = Vec::<Fr>::new();
        let mock_prover = MockProver::run(DEGREE, &circuit, vec![instance.clone()]).unwrap();
        mock_prover.assert_satisfied();
    }
}
