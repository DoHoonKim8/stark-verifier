use crate::snark::context::RegionCtx;
use halo2_proofs::{
    circuit::{AssignedCell, Value},
    halo2curves::ff::PrimeField,
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Fixed, Selector},
    poly::Rotation,
};
use std::marker::PhantomData;

use crate::snark::bn245_poseidon::{
    constants::{
        MDS_MATRIX_BG, ROUND_CONSTANTS_BG, R_F_BN254_POSEIDON, R_P_BN254_POSEIDON, T_BN254_POSEIDON,
    },
    value::{bg_to_fe, full_round_value, partial_round_value},
};

#[derive(Clone, Debug)]
pub struct PoseidonBn254ChipConfig<F: PrimeField> {
    pub state: [Column<Advice>; T_BN254_POSEIDON],
    pub constants: [Column<Fixed>; T_BN254_POSEIDON],
    pub q_f: Selector,
    pub q_p: Selector,
    _maker: PhantomData<F>,
}

impl<F: PrimeField> PoseidonBn254ChipConfig<F> {
    pub fn configure(meta: &mut ConstraintSystem<F>) -> Self {
        let state = [(); T_BN254_POSEIDON].map(|_| meta.advice_column());
        let constants = [(); T_BN254_POSEIDON].map(|_| meta.fixed_column());
        let q_f = meta.selector();
        let q_p = meta.selector();
        state.iter().for_each(|s| meta.enable_equality(*s));

        meta.create_gate("partial round", |meta| {
            let next_state = state
                .iter()
                .map(|s| meta.query_advice(*s, Rotation::next()))
                .collect::<Vec<_>>();
            let state = state
                .iter()
                .map(|s| meta.query_advice(*s, Rotation::cur()))
                .collect::<Vec<_>>();
            let constants = constants
                .iter()
                .map(|c| meta.query_fixed(*c, Rotation::cur()))
                .collect::<Vec<_>>();
            let q = meta.query_selector(q_p);
            let after_constant = state
                .iter()
                .zip(constants.iter())
                .map(|(s, c)| s.clone() + c.clone())
                .collect::<Vec<_>>();
            let mut after_sbox = after_constant.clone();
            after_sbox[0] = after_sbox[0].clone()
                * after_sbox[0].clone()
                * after_sbox[0].clone()
                * after_sbox[0].clone()
                * after_sbox[0].clone();
            let mut after_mds = [(); T_BN254_POSEIDON].map(|_| Expression::Constant(F::from(0)));
            for i in 0..T_BN254_POSEIDON {
                for j in 0..T_BN254_POSEIDON {
                    after_mds[i] = after_mds[i].clone()
                        + after_sbox[j].clone()
                            * Expression::Constant(bg_to_fe::<F>(&MDS_MATRIX_BG[i][j]));
                }
            }
            let diffs = next_state
                .iter()
                .zip(after_mds.iter())
                .map(|(n, a)| q.clone() * (n.clone() - a.clone()))
                .collect::<Vec<_>>();
            diffs
        });
        meta.create_gate("full round", |meta| {
            let next_state = state
                .iter()
                .map(|s| meta.query_advice(*s, Rotation::next()))
                .collect::<Vec<_>>();
            let state = state
                .iter()
                .map(|s| meta.query_advice(*s, Rotation::cur()))
                .collect::<Vec<_>>();
            let constants = constants
                .iter()
                .map(|c| meta.query_fixed(*c, Rotation::cur()))
                .collect::<Vec<_>>();
            let q = meta.query_selector(q_f);
            let after_constant = state
                .iter()
                .zip(constants.iter())
                .map(|(s, c)| s.clone() + c.clone())
                .collect::<Vec<_>>();
            let mut after_sbox = after_constant.clone();
            for i in 0..T_BN254_POSEIDON {
                after_sbox[i] = after_sbox[i].clone()
                    * after_sbox[i].clone()
                    * after_sbox[i].clone()
                    * after_sbox[i].clone()
                    * after_sbox[i].clone();
            }
            let mut after_mds = [(); T_BN254_POSEIDON].map(|_| Expression::Constant(F::from(0)));
            for i in 0..T_BN254_POSEIDON {
                for j in 0..T_BN254_POSEIDON {
                    after_mds[i] = after_mds[i].clone()
                        + after_sbox[j].clone()
                            * Expression::Constant(bg_to_fe::<F>(&MDS_MATRIX_BG[i][j]));
                }
            }
            let diffs = next_state
                .iter()
                .zip(after_mds.iter())
                .map(|(n, a)| q.clone() * (n.clone() - a.clone()))
                .collect::<Vec<_>>();
            diffs
        });

        Self {
            state,
            constants,
            q_p,
            q_f,
            _maker: PhantomData,
        }
    }
}

#[derive(Clone, Debug)]
pub struct PoseidonBn254Chip<F: PrimeField> {
    config: PoseidonBn254ChipConfig<F>,
}

impl<F: PrimeField> PoseidonBn254Chip<F> {
    pub fn new(config: &PoseidonBn254ChipConfig<F>) -> Self {
        PoseidonBn254Chip {
            config: config.clone(),
        }
    }

    pub fn assign_initial_state(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        state: [Value<F>; T_BN254_POSEIDON],
    ) -> Result<[AssignedCell<F, F>; T_BN254_POSEIDON], Error> {
        let state_assigned = state
            .iter()
            .zip(self.config.state.iter())
            .map(|(s, c)| ctx.assign_advice(|| "", *c, *s))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(state_assigned.try_into().unwrap())
    }

    // assume that the state is already assigned and apply partial round
    fn assign_partial_round(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        state: [Value<F>; T_BN254_POSEIDON],
        counter: &mut usize,
    ) -> Result<[AssignedCell<F, F>; T_BN254_POSEIDON], Error> {
        ctx.enable(self.config.q_p.clone())?;
        self.config
            .constants
            .iter()
            .zip(ROUND_CONSTANTS_BG[*counter..*counter + T_BN254_POSEIDON].iter())
            .map(|(c, r)| ctx.assign_fixed(|| "", *c, bg_to_fe::<F>(r)))
            .collect::<Result<Vec<_>, _>>()?;
        ctx.next();
        // assign next
        let mut state = state.clone();
        partial_round_value(&mut state, counter);
        let new_state_assigned = state
            .iter()
            .zip(self.config.state.iter())
            .map(|(s, c)| ctx.assign_advice(|| "", *c, *s))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(new_state_assigned.try_into().unwrap())
    }

    fn assign_full_round(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        state: [Value<F>; T_BN254_POSEIDON],
        counter: &mut usize,
    ) -> Result<[AssignedCell<F, F>; T_BN254_POSEIDON], Error> {
        ctx.enable(self.config.q_f.clone())?;
        self.config
            .constants
            .iter()
            .zip(ROUND_CONSTANTS_BG[*counter..*counter + T_BN254_POSEIDON].iter())
            .map(|(c, r)| ctx.assign_fixed(|| "", *c, bg_to_fe::<F>(r)))
            .collect::<Result<Vec<_>, _>>()?;
        ctx.next();
        // assign next
        let mut state = state.clone();
        full_round_value(&mut state, counter);
        let new_state_assigned = state
            .iter()
            .zip(self.config.state.iter())
            .map(|(s, c)| ctx.assign_advice(|| "", *c, *s))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(new_state_assigned.try_into().unwrap())
    }

    pub fn apply_permute(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        state: [AssignedCell<F, F>; T_BN254_POSEIDON],
    ) -> Result<[AssignedCell<F, F>; T_BN254_POSEIDON], Error> {
        let mut counter = 0;

        let state_value = state.iter().map(|s| s.value().cloned()).collect::<Vec<_>>();
        // re-assign state to the current row.
        let state_assigned = self.assign_initial_state(ctx, state_value.try_into().unwrap())?;
        for i in 0..T_BN254_POSEIDON {
            ctx.constrain_equal(state[i].cell(), state_assigned[i].cell())?;
        }

        let mut state = state;
        for _ in 0..R_F_BN254_POSEIDON / 2 {
            let state_value = state.iter().map(|s| s.value().cloned()).collect::<Vec<_>>();
            state = self.assign_full_round(ctx, state_value.try_into().unwrap(), &mut counter)?;
        }
        for _ in 0..R_P_BN254_POSEIDON {
            let state_value = state.iter().map(|s| s.value().cloned()).collect::<Vec<_>>();
            state =
                self.assign_partial_round(ctx, state_value.try_into().unwrap(), &mut counter)?;
        }
        for _ in 0..R_F_BN254_POSEIDON / 2 {
            let state_value = state.iter().map(|s| s.value().cloned()).collect::<Vec<_>>();
            state = self.assign_full_round(ctx, state_value.try_into().unwrap(), &mut counter)?;
        }
        ctx.next();
        Ok(state)
    }
}

#[cfg(test)]
mod tests {
    use crate::snark::context::RegionCtx;
    use halo2_proofs::{
        circuit::{floor_planner::V1, Layouter, Value},
        dev::MockProver,
        halo2curves::bn256::Fr,
        plonk::{Circuit, ConstraintSystem, Error},
    };

    use crate::snark::bn245_poseidon::native::permute_bn254_poseidon_native;

    use super::{PoseidonBn254Chip, PoseidonBn254ChipConfig};

    #[derive(Clone, Default)]
    pub struct TestCircuit;

    impl Circuit<Fr> for TestCircuit {
        type Config = PoseidonBn254ChipConfig<Fr>;
        type FloorPlanner = V1;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
            PoseidonBn254ChipConfig::<Fr>::configure(meta)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fr>,
        ) -> Result<(), Error> {
            let poseidon_chip = PoseidonBn254Chip::new(&config);
            layouter.assign_region(
                || "test",
                |region| {
                    let mut ctx = RegionCtx::new(region, 0);

                    let initial_state = [
                        Value::known(Fr::from(0)),
                        Value::known(Fr::from(1)),
                        Value::known(Fr::from(2)),
                        Value::known(Fr::from(3)),
                        Value::known(Fr::from(4)),
                    ];
                    let mut state = poseidon_chip.assign_initial_state(&mut ctx, initial_state)?;
                    state = poseidon_chip.apply_permute(&mut ctx, state)?;
                    for _ in 0..1200 {
                        state = poseidon_chip.apply_permute(&mut ctx, state)?;
                    }
                    Ok(())
                },
            )?;
            Ok(())
        }
    }

    #[test]
    fn test_poseidon_mock() {
        const DEGREE: u32 = 17;
        let circuit = TestCircuit;
        let mock_prover = MockProver::run(DEGREE, &circuit, vec![]).unwrap();
        mock_prover.assert_satisfied();

        let mut state = [
            Fr::from(0),
            Fr::from(1),
            Fr::from(2),
            Fr::from(3),
            Fr::from(4),
        ];
        permute_bn254_poseidon_native(&mut state);
    }
}
