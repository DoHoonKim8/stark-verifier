use std::marker::PhantomData;

use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Value},
    plonk::{
        Advice, Column, ConstraintSystem, Error, Expression, Fixed, Instance, Selector, TableColumn,
    },
    poly::Rotation,
};
use halo2curves::FieldExt;
use halo2wrong::RegionCtx;
use halo2wrong_maingate::{big_to_fe, decompose, fe_to_big};
use num_bigint::BigUint;
use num_integer::Integer;

pub const GOLDILOCKS_MODULUS: u64 = ((1 << 32) - 1) * (1 << 32) + 1;

// a*b + c = q*p + r, with range check of q and r
#[derive(Clone, Debug)]
pub struct ArithmeticChipConfig<F: FieldExt> {
    pub a: Column<Advice>,
    pub b: Column<Advice>,
    pub c: Column<Advice>,
    pub q: Column<Advice>,
    pub r: Column<Advice>,
    pub q_limbs: [Column<Advice>; 5],
    pub r_limbs: [Column<Advice>; 4],
    pub table: TableColumn,
    pub instance: Column<Instance>,
    pub constant: Column<Fixed>,
    pub selector: Selector,
    _marker: PhantomData<F>,
}

impl<F: FieldExt> ArithmeticChipConfig<F> {
    pub fn configure(meta: &mut ConstraintSystem<F>) -> Self {
        let a = meta.advice_column();
        let b = meta.advice_column();
        let c = meta.advice_column();
        let q = meta.advice_column();
        let r = meta.advice_column();
        let q_limbs = [(); 5].map(|_| meta.advice_column());
        let r_limbs = [(); 4].map(|_| meta.advice_column());

        let constant = meta.fixed_column();
        let selector = meta.selector();
        let table = meta.lookup_table_column();
        let instance = meta.instance_column();

        meta.enable_equality(a);
        meta.enable_equality(b);
        meta.enable_equality(c);
        meta.enable_equality(r);
        meta.enable_equality(instance);
        meta.enable_constant(constant);

        meta.create_gate("main constraint", |meta| {
            let s = meta.query_selector(selector);
            let a = meta.query_advice(a, Rotation::cur());
            let b = meta.query_advice(b, Rotation::cur());
            let c = meta.query_advice(c, Rotation::cur());
            let q = meta.query_advice(q, Rotation::cur());
            let q_limbs = q_limbs
                .map(|l| meta.query_advice(l, Rotation::cur()))
                .to_vec();
            let q_acc = (0..5).fold(Expression::Constant(F::zero()), |acc, i| {
                acc + q_limbs[i].clone() * Expression::Constant(F::from_u128(1u128 << (i * 16)))
            });
            let r = meta.query_advice(r, Rotation::cur());
            let r_limbs = r_limbs
                .map(|l| meta.query_advice(l, Rotation::cur()))
                .to_vec();
            let r_acc = (0..4).fold(Expression::Constant(F::zero()), |acc, i| {
                acc + r_limbs[i].clone() * Expression::Constant(F::from_u128(1u128 << (i * 16)))
            });
            let p = Expression::Constant(F::from(GOLDILOCKS_MODULUS));
            vec![
                s.clone() * (a * b + c - p * q.clone() - r.clone()),
                s.clone() * (q - q_acc),
                s.clone() * (r - r_acc),
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
            selector,
            _marker: PhantomData,
        }
    }
}

pub struct AssignedArithmetic<F: FieldExt> {
    pub a: AssignedCell<F, F>,
    pub b: AssignedCell<F, F>,
    pub c: AssignedCell<F, F>,
    pub r: AssignedCell<F, F>,
    pub constant: AssignedCell<F, F>,
}

#[derive(Clone)]
pub enum Term<'a, F: FieldExt> {
    Assigned(&'a AssignedCell<F, F>),
    Unassigned(Value<F>),
    Fixed(F),
}

#[derive(Clone, Debug)]
pub struct ArithmeticChip<F: FieldExt> {
    config: ArithmeticChipConfig<F>,
}

impl<F: FieldExt> ArithmeticChip<F> {
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

    pub fn assign_fixed(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        constant: F,
    ) -> Result<AssignedCell<F, F>, Error> {
        let assigned = self.apply(
            ctx,
            Term::Fixed(constant),
            Term::Unassigned(Value::known(F::zero())),
            Term::Unassigned(Value::known(F::zero())),
        )?;
        Ok(assigned.a)
    }

    pub fn assign_value(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        unassigned: Value<F>,
    ) -> Result<AssignedCell<F, F>, Error> {
        let assigned = self.apply(
            ctx,
            Term::Unassigned(Value::known(F::zero())),
            Term::Fixed(F::zero()),
            Term::Unassigned(unassigned.clone()),
        )?;
        Ok(assigned.c)
    }

    pub fn assign(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        a: Value<F>,
        b: Value<F>,
        c: Value<F>,
        constant: F,
    ) -> Result<AssignedArithmetic<F>, Error> {
        ctx.enable(self.config.selector)?;
        let tmp = a * b + c;
        let (q, r) = tmp
            .map(|t| {
                let (q, r) = fe_to_big(t).div_rem(&BigUint::from(GOLDILOCKS_MODULUS));
                (big_to_fe::<F>(q), big_to_fe::<F>(r))
            })
            .unzip();
        let q_limb = q.map(|x| decompose(x, 5, 16)).transpose_vec(5);
        let r_limb = r.map(|x| decompose(x, 4, 16)).transpose_vec(4);
        let a_assigned = ctx.assign_advice(|| "a", self.config.a, a)?;
        let b_assigned = ctx.assign_advice(|| "b", self.config.b, b)?;
        let c_assigned = ctx.assign_advice(|| "c", self.config.c, c)?;
        ctx.assign_advice(|| "q", self.config.q, q)?;
        let r_assigned = ctx.assign_advice(|| "r", self.config.r, r)?;
        self.config
            .q_limbs
            .iter()
            .zip(q_limb.iter())
            .map(|(limb_col, limb)| ctx.assign_advice(|| "", *limb_col, *limb))
            .collect::<Result<Vec<_>, Error>>()?;
        self.config
            .r_limbs
            .iter()
            .zip(r_limb.iter())
            .map(|(limb_col, limb)| ctx.assign_advice(|| "", *limb_col, *limb))
            .collect::<Result<Vec<_>, Error>>()?;
        let constant_assigned = ctx.assign_fixed(|| "fixed", self.config.constant, constant)?;
        ctx.next();
        Ok(AssignedArithmetic {
            a: a_assigned,
            b: b_assigned,
            c: c_assigned,
            r: r_assigned,
            constant: constant_assigned,
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
        let mut fixed = None;
        let unassigned = inputs
            .iter()
            .map(|x| {
                let x = match x {
                    Term::Assigned(x) => x.value().cloned(),
                    Term::Unassigned(x) => x.clone(),
                    Term::Fixed(x) => {
                        assert!(fixed.is_none(), "too many fixed input");
                        fixed = Some(x.clone());
                        Value::known(x.clone())
                    }
                };
                x
            })
            .collect::<Vec<_>>();
        let constant = if fixed.is_some() {
            fixed.unwrap()
        } else {
            F::zero()
        };
        let assigned = self.assign(ctx, unassigned[0], unassigned[1], unassigned[2], constant)?;
        let assigned_terms = vec![&assigned.a, &assigned.b, &assigned.c];
        // constrain
        for (input_term, assigned_term) in inputs.iter().zip(assigned_terms.iter()) {
            match input_term {
                Term::Assigned(input_term) => self.assert_equal(ctx, input_term, assigned_term)?,
                Term::Unassigned(_) => (),
                Term::Fixed(_) => self.assert_equal(ctx, &assigned.constant, assigned_term)?,
            }
        }
        Ok(assigned)
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

#[cfg(test)]
mod tests {
    use std::{fs::File, io::Write};

    use halo2_proofs::{
        circuit::{floor_planner::V1, Layouter},
        dev::MockProver,
        halo2curves::bn256::{Bn256, Fr},
        plonk::{Circuit, ConstraintSystem, Error},
        poly::kzg::commitment::ParamsKZG,
    };
    use halo2wrong::RegionCtx;
    use snark_verifier::loader::evm::encode_calldata;

    use crate::snark::verifier_api::EvmVerifier;

    use super::ArithmeticChipConfig;

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
                || "Verify proof",
                |region| {
                    let ctx = &mut RegionCtx::new(region, 0);
                    let a = chip.assign_fixed(ctx, Fr::from(1u64))?;
                    let _b = chip.assign_value(ctx, a.value().cloned())?;
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

    #[test]
    fn test_arithmetic_contract() {
        const DEGREE: u32 = 17;

        let circuit = TestCircuit;
        let instance = vec![];
        let mock_prover = MockProver::run(DEGREE, &circuit, vec![instance.clone()]).unwrap();
        mock_prover.assert_satisfied();
        println!("{}", "Mock prover passes");

        let srs: ParamsKZG<Bn256> = EvmVerifier::gen_srs(DEGREE);
        let pk = EvmVerifier::gen_pk(&srs, &circuit);
        let proof = EvmVerifier::gen_proof(&srs, &pk, circuit.clone(), vec![instance.clone()]);

        let deployment_code =
            EvmVerifier::gen_evm_verifier(&srs, pk.get_vk(), vec![instance.len()]);
        let calldata = encode_calldata::<Fr>(&[instance], &proof);
        let deployment_code_hex = "0x".to_string() + &hex::encode(deployment_code);
        let calldata_hex = "0x".to_string() + &hex::encode(calldata);
        let mut file = File::create("deployment_code.txt").unwrap();
        file.write_all(deployment_code_hex.as_bytes()).unwrap();
        let mut file = File::create("calldata.txt").unwrap();
        file.write_all(calldata_hex.as_bytes()).unwrap();
    }
}
