use std::marker::PhantomData;

use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Value},
    halo2curves::ff::PrimeField,
    plonk::{
        Advice, Column, ConstraintSystem, Error, Expression, Fixed, Instance, Selector, TableColumn,
    },
    poly::Rotation,
};
use halo2wrong_maingate::{big_to_fe, decompose, fe_to_big};
use num_bigint::BigUint;
use num_integer::Integer;

use crate::plonky2_verifier::context::RegionCtx;

use super::utils::goldilocks_decompose;

pub const GOLDILOCKS_MODULUS: u64 = ((1 << 32) - 1) * (1 << 32) + 1;

const Q_LIMBS: usize = 5;

// a*b + c = q*p + r, with range check of q and r
#[derive(Clone, Debug)]
pub struct ArithmeticChipConfig<F: PrimeField> {
    pub a: Column<Advice>,
    pub b: Column<Advice>,
    pub c: Column<Advice>,
    pub q: Column<Advice>,
    pub r: Column<Advice>,
    pub q_limbs: [Column<Advice>; Q_LIMBS],
    pub r_limbs: [Column<Advice>; 4],
    pub table: TableColumn,
    pub instance: Column<Instance>,
    pub constant: Column<Fixed>,
    pub s_limb: Selector,  // limb decomposition of q and r
    pub s_range: Selector, // contraint q = p - r
    pub s_base: Selector,  // contraint a*b + c == q*p + r
    pub s_ext: Selector,   // contraint a*b + c == q*p + r on extension field
    _marker: PhantomData<F>,
}

impl<F: PrimeField> ArithmeticChipConfig<F> {
    pub fn configure(meta: &mut ConstraintSystem<F>) -> Self {
        let a = meta.advice_column();
        let b = meta.advice_column();
        let c = meta.advice_column();
        let q = meta.advice_column();
        let r = meta.advice_column();
        let q_limbs = [(); Q_LIMBS].map(|_| meta.advice_column());
        let r_limbs = [(); 4].map(|_| meta.advice_column());

        let constant = meta.fixed_column();
        let s_limb = meta.selector();
        let s_range = meta.selector();
        let s_base = meta.selector();
        let s_ext = meta.selector();

        let table = meta.lookup_table_column();
        let instance = meta.instance_column();

        meta.enable_equality(a);
        meta.enable_equality(b);
        meta.enable_equality(c);
        meta.enable_equality(r);
        meta.enable_equality(q);
        meta.enable_equality(instance);
        meta.enable_constant(constant);

        meta.create_gate("limb decomposition", |meta| {
            let s_limb = meta.query_selector(s_limb);
            let q = meta.query_advice(q, Rotation::cur());
            let q_limbs = q_limbs
                .map(|l| meta.query_advice(l, Rotation::cur()))
                .to_vec();
            let q_acc = (0..Q_LIMBS).fold(Expression::Constant(F::from(0)), |acc, i| {
                acc + q_limbs[i].clone() * Expression::Constant(F::from_u128(1u128 << (i * 16)))
            });
            let r = meta.query_advice(r, Rotation::cur());
            let r_limbs = r_limbs
                .map(|l| meta.query_advice(l, Rotation::cur()))
                .to_vec();
            let r_acc = (0..4).fold(Expression::Constant(F::from(0)), |acc, i| {
                acc + r_limbs[i].clone() * Expression::Constant(F::from_u128(1u128 << (i * 16)))
            });
            vec![s_limb.clone() * (q - q_acc), s_limb.clone() * (r - r_acc)]
        });

        // This custom gate ensures that r satisfies 0 <= r < GOLDILOCKS_MODULUS when s_range is enabled.
        meta.create_gate("q = p - r", |meta| {
            let q = meta.query_advice(q, Rotation::cur());
            let r = meta.query_advice(r, Rotation::cur());
            let p = Expression::Constant(F::from(GOLDILOCKS_MODULUS));
            let s_range = meta.query_selector(s_range);
            vec![s_range * (q - p + r)]
        });

        meta.create_gate("base field constraint", |meta| {
            let s_base = meta.query_selector(s_base);
            let a = meta.query_advice(a, Rotation::cur());
            let b = meta.query_advice(b, Rotation::cur());
            let c = meta.query_advice(c, Rotation::cur());
            let q = meta.query_advice(q, Rotation::cur());
            let r = meta.query_advice(r, Rotation::cur());
            let p = Expression::Constant(F::from(GOLDILOCKS_MODULUS));
            vec![s_base.clone() * (a * b + c - p * q.clone() - r.clone())]
        });

        meta.create_gate("extension field contraint", |meta| {
            let s_ext = meta.query_selector(s_ext);
            let a_x = meta.query_advice(a, Rotation::cur());
            let a_y = meta.query_advice(a, Rotation::next());
            let b_x = meta.query_advice(b, Rotation::cur());
            let b_y = meta.query_advice(b, Rotation::next());
            let c_x = meta.query_advice(c, Rotation::cur());
            let c_y = meta.query_advice(c, Rotation::next());
            let q_x = meta.query_advice(q, Rotation::cur());
            let q_y = meta.query_advice(q, Rotation::next());
            let r_x = meta.query_advice(r, Rotation::cur());
            let r_y = meta.query_advice(r, Rotation::next());
            let p = Expression::Constant(F::from(GOLDILOCKS_MODULUS));
            let left_x = a_x.clone() * b_x.clone()
                + Expression::Constant(F::from(7)) * a_y.clone() * b_y.clone()
                + c_x.clone();
            let left_y = a_x.clone() * b_y.clone() + a_y.clone() * b_x.clone() + c_y.clone();
            let right_x = p.clone() * q_x.clone() + r_x.clone();
            let right_y = p.clone() * q_y.clone() + r_y.clone();
            vec![
                s_ext.clone() * (left_x - right_x),
                s_ext.clone() * (left_y - right_y),
            ]
        });

        q_limbs.iter().for_each(|limb| {
            meta.lookup("q_limbs range check", |meta| {
                let l = meta.query_advice(*limb, Rotation::cur());
                vec![(l, table)]
            });
        });
        r_limbs.iter().for_each(|limb| {
            meta.lookup("r_limbs range check", |meta| {
                let l = meta.query_advice(*limb, Rotation::cur());
                vec![(l, table)]
            });
        });
        ArithmeticChipConfig {
            a,
            b,
            c,
            q,
            r,
            q_limbs,
            r_limbs,
            table,
            instance,
            constant,
            s_limb,
            s_range,
            s_base,
            s_ext,
            _marker: PhantomData,
        }
    }
}

pub struct AssignedArithmetic<F: PrimeField> {
    pub a: AssignedCell<F, F>,
    pub b: AssignedCell<F, F>,
    pub c: AssignedCell<F, F>,
    pub r: AssignedCell<F, F>,
}

pub struct AssignedArithmeticExt<F: PrimeField> {
    pub a: [AssignedCell<F, F>; 2],
    pub b: [AssignedCell<F, F>; 2],
    pub c: [AssignedCell<F, F>; 2],
    pub r: [AssignedCell<F, F>; 2],
}

#[derive(Clone)]
pub enum Term<'a, F: PrimeField> {
    Assigned(&'a AssignedCell<F, F>),
    Unassigned(Value<F>),
}

#[derive(Clone)]
pub enum TermExt<'a, F: PrimeField> {
    Assigned(&'a [AssignedCell<F, F>; 2]),
    Unassigned([Value<F>; 2]),
}

#[derive(Clone, Debug)]
pub struct ArithmeticChip<F: PrimeField> {
    config: ArithmeticChipConfig<F>,
}

impl<F: PrimeField> ArithmeticChip<F> {
    pub fn new(config: &ArithmeticChipConfig<F>) -> Self {
        ArithmeticChip {
            config: config.clone(),
        }
    }

    pub fn expose_public(
        &self,
        mut layouter: impl Layouter<F>,
        value: AssignedCell<F, F>,
        row: usize,
    ) -> Result<(), Error> {
        layouter.constrain_instance(value.cell(), self.config.instance, row)
    }

    pub fn assert_equal(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        a: &AssignedCell<F, F>,
        b: &AssignedCell<F, F>,
    ) -> Result<(), Error> {
        ctx.constrain_equal(a.cell(), b.cell())?;
        Ok(())
    }

    pub fn assert_equal_ext(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        a: &[AssignedCell<F, F>; 2],
        b: &[AssignedCell<F, F>; 2],
    ) -> Result<(), Error> {
        for i in 0..2 {
            ctx.constrain_equal(a[i].cell(), b[i].cell())?;
        }
        Ok(())
    }

    //If the given constant is already assigned, return the cell. If not, assign it.
    pub fn assign_constant(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        constant: F,
    ) -> Result<AssignedCell<F, F>, Error> {
        let got = ctx.get_fixed(&constant);
        if let Some(assigned) = got {
            return Ok(assigned.clone());
        } else {
            // since constant_assigned.value() will be None in proving step, we return a_asigned instead.
            let a_assigned = ctx.assign_advice(|| "a", self.config.a, Value::known(constant))?;
            let constant_assined = ctx.assign_fixed(|| "fixed", self.config.constant, constant)?;
            ctx.next();
            self.assert_equal(ctx, &a_assigned, &constant_assined)?;
            ctx.register_fixed(constant, a_assigned.clone());
            Ok(a_assigned)
        }
    }

    // assign value with range check 0 <= x < GOLDILOCKS_MODULUS
    pub fn assign_value(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        unassigned: Value<F>,
    ) -> Result<AssignedCell<F, F>, Error> {
        ctx.enable(self.config.s_limb)?;
        ctx.enable(self.config.s_range)?;
        let r = unassigned.clone();
        let q = Value::known(F::from(GOLDILOCKS_MODULUS)) - r.clone();
        let (_q_assigned, r_assigned) = assign_q_and_r(&self.config, ctx, q, r)?;
        ctx.next();
        Ok(r_assigned)
    }

    // assert 0 <= x < GOLDILOCKS_MODULUS
    pub fn range_check(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        x: &AssignedCell<F, F>,
    ) -> Result<(), Error> {
        let assigned = self.assign_value(ctx, x.value().cloned())?;
        self.assert_equal(ctx, x, &assigned)?;
        Ok(())
    }

    fn assign(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        a: Value<F>,
        b: Value<F>,
        c: Value<F>,
    ) -> Result<AssignedArithmetic<F>, Error> {
        ctx.enable(self.config.s_base)?;
        ctx.enable(self.config.s_limb)?;
        let tmp = a * b + c;
        let (q, r) = tmp
            .map(|t| {
                let (q, r) = fe_to_big(t).div_rem(&BigUint::from(GOLDILOCKS_MODULUS));
                (big_to_fe::<F>(q), big_to_fe::<F>(r))
            })
            .unzip();
        let (_q_assigned, r_assigned) = assign_q_and_r(&self.config, ctx, q, r)?;
        let a_assigned = ctx.assign_advice(|| "a", self.config.a, a)?;
        let b_assigned = ctx.assign_advice(|| "b", self.config.b, b)?;
        let c_assigned = ctx.assign_advice(|| "c", self.config.c, c)?;
        ctx.next();
        Ok(AssignedArithmetic {
            a: a_assigned,
            b: b_assigned,
            c: c_assigned,
            r: r_assigned,
        })
    }

    fn assign_ext(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        a: [Value<F>; 2],
        b: [Value<F>; 2],
        c: [Value<F>; 2],
    ) -> Result<AssignedArithmeticExt<F>, Error> {
        ctx.enable(self.config.s_ext)?;
        ctx.enable(self.config.s_limb)?;
        let tmp_x = a[0] * b[0] + Value::known(F::from(7)) * a[1] * b[1] + c[0];
        let tmp_y = a[0] * b[1] + a[1] * b[0] + c[1];
        let (q_x, r_x) = tmp_x
            .map(|t| {
                let (q, r) = fe_to_big(t).div_rem(&BigUint::from(GOLDILOCKS_MODULUS));
                (big_to_fe::<F>(q), big_to_fe::<F>(r))
            })
            .unzip();
        let (q_y, r_y) = tmp_y
            .map(|t| {
                let (q, r) = fe_to_big(t).div_rem(&BigUint::from(GOLDILOCKS_MODULUS));
                (big_to_fe::<F>(q), big_to_fe::<F>(r))
            })
            .unzip();
        let (_q_x_assigned, r_x_assigned) = assign_q_and_r(&self.config, ctx, q_x, r_x)?;
        let a_x_assigned = ctx.assign_advice(|| "a", self.config.a, a[0])?;
        let b_x_assigned = ctx.assign_advice(|| "b", self.config.b, b[0])?;
        let c_x_assigned = ctx.assign_advice(|| "c", self.config.c, c[0])?;
        ctx.next();
        let (_q_y_assigned, r_y_assigned) = assign_q_and_r(&self.config, ctx, q_y, r_y)?;
        let a_y_assigned = ctx.assign_advice(|| "a", self.config.a, a[1])?;
        let b_y_assigned = ctx.assign_advice(|| "b", self.config.b, b[1])?;
        let c_y_assigned = ctx.assign_advice(|| "c", self.config.c, c[1])?;
        ctx.next();
        Ok(AssignedArithmeticExt {
            a: [a_x_assigned, a_y_assigned],
            b: [b_x_assigned, b_y_assigned],
            c: [c_x_assigned, c_y_assigned],
            r: [r_x_assigned, r_y_assigned],
        })
    }

    pub fn apply(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        a: Term<F>,
        b: Term<F>,
        c: Term<F>,
    ) -> Result<AssignedArithmetic<F>, Error> {
        let inputs = vec![a, b, c];
        let unassigned = inputs
            .iter()
            .map(|x| {
                let x = match x {
                    Term::Assigned(x) => x.value().cloned(),
                    Term::Unassigned(x) => x.clone(),
                };
                x
            })
            .collect::<Vec<_>>();
        let assigned = self.assign(ctx, unassigned[0], unassigned[1], unassigned[2])?;
        let assigned_terms = vec![&assigned.a, &assigned.b, &assigned.c];
        // constrain
        for (input_term, assigned_term) in inputs.iter().zip(assigned_terms.iter()) {
            match input_term {
                Term::Assigned(input_term) => self.assert_equal(ctx, input_term, assigned_term)?,
                Term::Unassigned(_) => (),
            }
        }
        Ok(assigned)
    }

    pub fn apply_ext(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        a: TermExt<F>,
        b: TermExt<F>,
        c: TermExt<F>,
    ) -> Result<AssignedArithmeticExt<F>, Error> {
        let inputs = vec![a, b, c];
        let unassigned = inputs
            .iter()
            .map(|x| {
                let x = match x {
                    TermExt::Assigned(x) => [x[0].value().cloned(), x[1].value().cloned()],
                    TermExt::Unassigned(x) => x.clone(),
                };
                x
            })
            .collect::<Vec<_>>();
        let assigned = self.assign_ext(ctx, unassigned[0], unassigned[1], unassigned[2])?;
        let assigned_terms = vec![&assigned.a, &assigned.b, &assigned.c];
        // constrain
        for (input_term, assigned_term) in inputs.iter().zip(assigned_terms.iter()) {
            match input_term {
                TermExt::Assigned(input_term) => {
                    self.assert_equal_ext(ctx, input_term, assigned_term)?
                }
                TermExt::Unassigned(_) => (),
            }
        }
        Ok(assigned)
    }

    // returns a*b + c without taking modulo
    fn mul_add_no_mod(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        a: &AssignedCell<F, F>,
        b: &AssignedCell<F, F>,
        c: &AssignedCell<F, F>,
    ) -> Result<AssignedCell<F, F>, Error> {
        ctx.enable(self.config.s_base)?;
        let zero = self.assign_constant(ctx, F::ZERO)?;
        let r = a.value().cloned() * b.value().cloned() + c.value().cloned();
        let a_reassigned = ctx.assign_advice(|| "a", self.config.a, a.value().cloned())?;
        let b_reassigned = ctx.assign_advice(|| "b", self.config.b, b.value().cloned())?;
        let c_reassigned = ctx.assign_advice(|| "c", self.config.c, c.value().cloned())?;
        let q_assinged = ctx.assign_advice(|| "q", self.config.q, Value::known(F::ZERO))?;
        let r_assigned = ctx.assign_advice(|| "r", self.config.r, r)?;
        ctx.next();

        // constrain
        self.assert_equal(ctx, a, &a_reassigned)?;
        self.assert_equal(ctx, b, &b_reassigned)?;
        self.assert_equal(ctx, c, &c_reassigned)?;
        self.assert_equal(ctx, &zero, &q_assinged)?;
        Ok(r_assigned)
    }

    fn inner_product_no_mod(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        x: &[AssignedCell<F, F>],
        y: &[AssignedCell<F, F>],
    ) -> Result<AssignedCell<F, F>, Error> {
        assert!(x.len() == y.len(), "x and y must have the same length");
        let mut acc = self.assign_constant(ctx, F::ZERO)?;
        for (x, y) in x.iter().zip(y.iter()) {
            acc = self.mul_add_no_mod(ctx, x, y, &acc)?;
        }
        Ok(acc)
    }

    // pack 3 goldilocks field elements to a single field element
    pub fn pack(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        x: [AssignedCell<F, F>; 3],
    ) -> Result<AssignedCell<F, F>, Error> {
        let coeff = (0..3)
            .map(|i| self.assign_constant(ctx, F::from(GOLDILOCKS_MODULUS).pow([i as u64])))
            .collect::<Result<Vec<_>, Error>>()?;
        self.inner_product_no_mod(ctx, &x, &coeff)
    }

    // unpack a field element to 3 goldilocks field elements
    pub fn unpack(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        x: &AssignedCell<F, F>,
    ) -> Result<[AssignedCell<F, F>; 3], Error> {
        let coeff = (0..4)
            .map(|i| self.assign_constant(ctx, F::from(GOLDILOCKS_MODULUS).pow([i as u64])))
            .collect::<Result<Vec<_>, Error>>()?;
        let decomposed_value = x
            .value()
            .cloned()
            .map(|x| goldilocks_decompose(x))
            .transpose_vec(4);
        let decomposed = decomposed_value
            .iter()
            .map(|x| self.assign_value(ctx, *x))
            .collect::<Result<Vec<_>, Error>>()?;
        let x_expected = self.inner_product_no_mod(ctx, &decomposed, &coeff)?;
        self.assert_equal(ctx, &x, &x_expected)?;
        Ok(decomposed[0..3].to_vec().try_into().unwrap())
    }

    pub fn load_table(
        &self,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), halo2_proofs::plonk::Error> {
        layouter.assign_table(
            || "range table",
            |mut table| {
                for offset in 0..1 << 16 {
                    table.assign_cell(
                        || "value",
                        self.config.table,
                        offset,
                        || Value::known(F::from(offset as u64)),
                    )?;
                }
                Ok(())
            },
        )?;
        Ok(())
    }
}

// assign q and r with limb decomposition
fn assign_q_and_r<F: PrimeField>(
    config: &ArithmeticChipConfig<F>,
    ctx: &mut RegionCtx<'_, F>,
    q: Value<F>,
    r: Value<F>,
) -> Result<(AssignedCell<F, F>, AssignedCell<F, F>), Error> {
    let q_limb = q.map(|x| decompose(x, Q_LIMBS, 16)).transpose_vec(Q_LIMBS);
    let r_limb = r.map(|x| decompose(x, 4, 16)).transpose_vec(4);
    config
        .q_limbs
        .iter()
        .zip(q_limb.iter())
        .map(|(limb_col, limb)| ctx.assign_advice(|| "", *limb_col, *limb))
        .collect::<Result<Vec<_>, Error>>()?;
    config
        .r_limbs
        .iter()
        .zip(r_limb.iter())
        .map(|(limb_col, limb)| ctx.assign_advice(|| "", *limb_col, *limb))
        .collect::<Result<Vec<_>, Error>>()?;
    let q_assigned = ctx.assign_advice(|| "q", config.q, q)?;
    let r_assigned = ctx.assign_advice(|| "r", config.r, r)?;
    Ok((q_assigned, r_assigned))
}

#[cfg(test)]
mod tests {
    use halo2_proofs::{
        circuit::{floor_planner::V1, Layouter},
        dev::MockProver,
        halo2curves::bn256::Fr,
        plonk::{Circuit, ConstraintSystem, Error},
    };

    use crate::plonky2_verifier::context::RegionCtx;

    use super::{ArithmeticChipConfig, TermExt};

    #[derive(Clone, Default)]
    pub struct TestCircuit;

    impl Circuit<Fr> for TestCircuit {
        type Config = ArithmeticChipConfig<Fr>;
        type FloorPlanner = V1;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
            ArithmeticChipConfig::<Fr>::configure(meta)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fr>,
        ) -> Result<(), Error> {
            let chip = super::ArithmeticChip::new(&config);
            chip.load_table(&mut layouter)?;

            layouter.assign_region(
                || "test arithmetic",
                |region| {
                    let ctx = &mut RegionCtx::new(region, 0);
                    let a = chip.assign_constant(ctx, Fr::from(1u64))?;
                    let _b = chip.assign_value(ctx, a.value().cloned())?;

                    let packed = chip.pack(ctx, [a.clone(), a.clone(), a.clone()])?;
                    let decomposed = chip.unpack(ctx, &packed)?;
                    for i in 0..3 {
                        chip.assert_equal(ctx, &a, &decomposed[i])?;
                    }
                    chip.range_check(ctx, &a)?;

                    let c_x = chip.assign_constant(ctx, Fr::from(1u64))?;
                    let c_y = chip.assign_constant(ctx, Fr::from(1u64))?;
                    let c = [c_x.clone(), c_y.clone()];
                    let _d = chip.apply_ext(
                        ctx,
                        TermExt::Assigned(&c),
                        TermExt::Assigned(&c),
                        TermExt::Assigned(&c),
                    )?;

                    Ok(())
                },
            )?;
            Ok(())
        }
    }

    #[test]
    fn test_arithmetic_chip_mock() {
        let circuit = TestCircuit;
        let instance = vec![];
        let mock_prover = MockProver::run(17, &circuit, vec![instance.clone()]).unwrap();
        mock_prover.assert_satisfied();
    }
}
