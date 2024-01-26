use halo2_proofs::{
    arithmetic::Field,
    circuit::{AssignedCell, Layouter, Value},
    plonk::Error,
};
use halo2curves::{goldilocks::fp::Goldilocks, FieldExt};
use halo2wrong::RegionCtx;
use halo2wrong_maingate::{big_to_fe, fe_to_big, AssignedCondition, AssignedValue};
use num_bigint::BigUint;
use num_traits::Num;

use halo2wrong_maingate::Term as MainGateTerm;

use super::native_chip::arithmetic_chip::{ArithmeticChip, ArithmeticChipConfig, Term};

#[derive(Clone, Debug)]
pub struct GoldilocksChipConfig<F: FieldExt> {
    arithmetic_config: ArithmeticChipConfig<F>,
}

pub struct GoldilocksChip<F: FieldExt> {
    goldilocks_chip_config: GoldilocksChipConfig<F>,
}

impl<F: FieldExt> GoldilocksChip<F> {
    pub fn configure(arithmetic_chip_config: &ArithmeticChipConfig<F>) -> GoldilocksChipConfig<F> {
        GoldilocksChipConfig {
            arithmetic_config: arithmetic_chip_config.clone(),
        }
    }

    pub fn new(goldilocks_chip_config: &GoldilocksChipConfig<F>) -> Self {
        Self {
            goldilocks_chip_config: goldilocks_chip_config.clone(),
        }
    }

    pub fn arithmetic_chip(&self) -> ArithmeticChip<F> {
        ArithmeticChip::new(&self.goldilocks_chip_config.arithmetic_config)
    }

    pub fn goldilocks_modulus(&self) -> BigUint {
        BigUint::from_str_radix(&Goldilocks::MODULUS[2..], 16).unwrap()
    }

    pub fn goldilocks_to_native_fe(&self, goldilocks: Goldilocks) -> F {
        big_to_fe::<F>(fe_to_big::<Goldilocks>(goldilocks))
    }

    // assumes `fe` is already in goldilocks field
    fn native_fe_to_goldilocks(&self, fe: F) -> Goldilocks {
        big_to_fe::<Goldilocks>(fe_to_big::<F>(fe))
    }

    pub fn assign_value(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        unassigned: Value<F>,
    ) -> Result<AssignedValue<F>, Error> {
        self.arithmetic_chip().assign_value(ctx, unassigned)
    }

    pub fn compose(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        terms: &[MainGateTerm<F>],
        constant: Goldilocks,
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

    pub fn assign_constant(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        constant: Goldilocks,
    ) -> Result<AssignedValue<F>, Error> {
        self.arithmetic_chip()
            .assign_fixed(ctx, self.goldilocks_to_native_fe(constant))
    }

    pub fn add(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        lhs: &AssignedValue<F>,
        rhs: &AssignedValue<F>,
    ) -> Result<AssignedValue<F>, Error> {
        let assigned = self.arithmetic_chip().apply(
            ctx,
            Term::Assigned(lhs),
            Term::Fixed(F::one()),
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
        let assigned = self.arithmetic_chip().apply(
            ctx,
            Term::Assigned(rhs),
            Term::Fixed(self.goldilocks_to_native_fe(-Goldilocks::one())),
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
        self.mul_add_constant(ctx, lhs, rhs, Goldilocks::zero())
    }
    /// `lhs * rhs * constant`
    pub fn mul_with_constant(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        lhs: &AssignedValue<F>,
        rhs: &AssignedValue<F>,
        constant: Goldilocks,
    ) -> Result<AssignedValue<F>, Error> {
        let mul_assigned = self.arithmetic_chip().apply(
            ctx,
            Term::Assigned(lhs),
            Term::Assigned(rhs),
            Term::Fixed(F::zero()),
        )?;
        let zero_assigned = mul_assigned.c;
        let assigned = self.arithmetic_chip().apply(
            ctx,
            Term::Assigned(&mul_assigned.r),
            Term::Fixed(self.goldilocks_to_native_fe(constant)),
            Term::Assigned(&zero_assigned),
        )?;
        Ok(assigned.r)
    }

    pub fn mul_add_constant(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        a: &AssignedValue<F>,
        b: &AssignedValue<F>,
        to_add: Goldilocks,
    ) -> Result<AssignedValue<F>, Error> {
        let assigned = self.arithmetic_chip().apply(
            ctx,
            Term::Assigned(a),
            Term::Assigned(b),
            Term::Fixed(self.goldilocks_to_native_fe(to_add)),
        )?;
        Ok(assigned.r)
    }

    fn mul_const_add(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        a: &AssignedValue<F>,
        constant: Goldilocks,
        b: &AssignedValue<F>,
    ) -> Result<AssignedValue<F>, Error> {
        let assigned = self.arithmetic_chip().apply(
            ctx,
            Term::Assigned(a),
            Term::Fixed(self.goldilocks_to_native_fe(constant)),
            Term::Assigned(b),
        )?;
        Ok(assigned.r)
    }

    pub fn add_constant(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        a: &AssignedValue<F>,
        constant: Goldilocks,
    ) -> Result<AssignedValue<F>, Error> {
        let one = self.assign_constant(ctx, Goldilocks::one())?;
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

    fn assign_bit(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        zero: &AssignedCell<F, F>,
        one: &AssignedCell<F, F>,
        bit: &Value<F>,
    ) -> Result<AssignedValue<F>, Error> {
        let assigned = self.arithmetic_chip().apply(
            ctx,
            Term::Unassigned(bit.clone()),
            Term::Assigned(one),
            Term::Fixed(self.goldilocks_to_native_fe(-Goldilocks::one())),
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
        let a_minus_b_cond = self.mul(ctx, &a_minus_b, &cond)?;
        self.add(ctx, &a_minus_b_cond, b)
    }

    // 4 rows
    pub fn is_zero(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        a: &AssignedValue<F>,
    ) -> Result<AssignedCondition<F>, Error> {
        let a_inv = a.value().map(|a| {
            let a = self.native_fe_to_goldilocks(*a);
            if a == Goldilocks::zero() {
                F::zero()
            } else {
                big_to_fe(fe_to_big::<Goldilocks>(a.invert().unwrap()))
            }
        });
        let assigned = self.arithmetic_chip().apply(
            ctx,
            Term::Assigned(a),
            Term::Unassigned(a_inv),
            Term::Fixed(F::zero()),
        )?;
        let a_a_inv = assigned.r;
        let zero = assigned.c;
        let one = self.assign_constant(ctx, Goldilocks::one())?;
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
        let zero = self.assign_constant(ctx, Goldilocks::zero())?;
        let one = self.assign_constant(ctx, Goldilocks::one())?;
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
            .map(|bit| self.assign_bit(ctx, &zero, &one, bit))
            .collect::<Result<Vec<_>, Error>>()?;

        let acc = bit_assigned.iter().enumerate().fold(
            Ok(zero),
            |acc: Result<AssignedCell<F, F>, Error>, (i, bit)| {
                let acc = acc?;
                let assigned = self.arithmetic_chip().apply(
                    ctx,
                    Term::Assigned(bit),
                    Term::Fixed(F::from(1 << i)),
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
        let zero = self.assign_constant(ctx, Goldilocks::zero())?;
        let acc = bits.iter().enumerate().fold(
            Ok(zero),
            |acc: Result<AssignedCell<F, F>, Error>, (i, bit)| {
                let acc = acc?;
                let assigned = self.arithmetic_chip().apply(
                    ctx,
                    Term::Assigned(bit),
                    Term::Fixed(F::from(1 << i)),
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
        base: Goldilocks,
        power_bits: &[AssignedValue<F>],
    ) -> Result<AssignedValue<F>, Error> {
        let mut x = self.assign_constant(ctx, Goldilocks::one())?;
        let one = self.assign_constant(ctx, Goldilocks::one())?;
        for (i, bit) in power_bits.iter().enumerate() {
            let is_zero_bit = self.is_zero(ctx, bit)?;
            let power = u64::from(1u64 << i).to_le();
            let base = self.assign_constant(ctx, base.pow(&[power, 0, 0, 0]))?;
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
        halo2curves::bn256::{Bn256, Fr},
        plonk::{Circuit, ConstraintSystem, Error},
        poly::kzg::commitment::ParamsKZG,
    };
    use halo2curves::goldilocks::fp::Goldilocks;
    use halo2wrong::RegionCtx;

    use crate::snark::{
        chip::native_chip::arithmetic_chip::{ArithmeticChipConfig, GOLDILOCKS_MODULUS},
        verifier_api::EvmVerifier,
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
            let arithmetic_config = ArithmeticChipConfig::configure(meta);
            GoldilocksChipConfig { arithmetic_config }
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

                    let a = chip.assign_constant(ctx, Goldilocks::from(GOLDILOCKS_MODULUS - 2))?;
                    let b = chip.assign_constant(ctx, Goldilocks::from(3))?;
                    let _c = chip.add(ctx, &a, &b)?;

                    // let a_bits = chip.to_bits(ctx, &a, 64)?;
                    // let a_recovered = chip.from_bits(ctx, &a_bits)?;

                    // chip.assert_equal(ctx, &a, &a_recovered)?;

                    // let cond = chip.assign_constant(ctx, Goldilocks::one())?;

                    // let selected = chip.select(ctx, &a, &b, &cond)?;
                    // chip.assert_equal(ctx, &selected, &a)?;

                    // let should_zero = chip.is_zero(ctx, &a)?;
                    // let zero = chip.assign_constant(ctx, Goldilocks::zero())?;
                    // let should_one = chip.is_zero(ctx, &zero)?;
                    // let one = chip.assign_constant(ctx, Goldilocks::one())?;

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

        // generates EVM verifier
        let srs: ParamsKZG<Bn256> = EvmVerifier::gen_srs(DEGREE);
        let pk = EvmVerifier::gen_pk(&srs, &circuit);
        let _proof = EvmVerifier::gen_proof(&srs, &pk, circuit.clone(), vec![instance.clone()]);
    }
}
