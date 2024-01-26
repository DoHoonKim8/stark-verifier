use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    dev::MockProver,
    halo2curves::bn256::{Bn256, Fr},
    plonk::{Circuit, ConstraintSystem},
    poly::kzg::commitment::ParamsKZG,
};
use halo2curves::goldilocks::fp::Goldilocks;
use halo2wrong::RegionCtx;
use halo2wrong_maingate::{big_to_fe, fe_to_big};
use plonky2::{
    field::types::Sample,
    field::{
        extension::{quadratic::QuadraticExtension, Extendable},
        goldilocks_field::GoldilocksField,
    },
    gates::gate::Gate,
    hash::hash_types::HashOut,
    plonk::vars::EvaluationVars,
};

use super::CustomGateConstrainer;
use crate::snark::{
    chip::{
        goldilocks_chip::{GoldilocksChip, GoldilocksChipConfig},
        native_chip::arithmetic_chip::ArithmeticChipConfig,
    },
    types::{
        self,
        assigned::{AssignedExtensionFieldValue, AssignedHashValues},
    },
    verifier_api::EvmVerifier,
};

const D: usize = 2;
type F = GoldilocksField;
type FE = <GoldilocksField as Extendable<D>>::Extension;

#[derive(Clone)]
struct TestCircuit<'a, Gate: CustomGateConstrainer<Fr>> {
    gate: Gate,
    evaluation_vars: EvaluationVars<'a, F, D>,
    output: Vec<QuadraticExtension<F>>,
}

fn goldilocks_to_fr(x: GoldilocksField) -> Fr {
    big_to_fe(fe_to_big::<Goldilocks>(types::to_goldilocks(x)))
}

fn assign_quadratic_extensions(
    ctx: &mut RegionCtx<'_, Fr>,
    goldilocks_chip: &GoldilocksChip<Fr>,
    input: &[QuadraticExtension<F>],
) -> Vec<AssignedExtensionFieldValue<Fr, 2>> {
    input
        .iter()
        .map(|x| {
            let a_assigned = goldilocks_chip
                .assign_value(ctx, Value::known(goldilocks_to_fr(x.0[0])))
                .unwrap();
            let b_assigned = goldilocks_chip
                .assign_value(ctx, Value::known(goldilocks_to_fr(x.0[1])))
                .unwrap();
            AssignedExtensionFieldValue([a_assigned, b_assigned])
        })
        .collect::<Vec<_>>()
}

fn assign_hash_values(
    ctx: &mut RegionCtx<'_, Fr>,
    goldilocks_chip: &GoldilocksChip<Fr>,
    input: &HashOut<F>,
) -> AssignedHashValues<Fr> {
    let elements = input
        .elements
        .iter()
        .map(|e| {
            goldilocks_chip
                .assign_value(ctx, Value::known(goldilocks_to_fr(*e)))
                .unwrap()
        })
        .collect::<Vec<_>>();
    AssignedHashValues {
        elements: elements.try_into().unwrap(),
    }
}

impl<'a, Gate: CustomGateConstrainer<Fr>> Circuit<Fr> for TestCircuit<'a, Gate> {
    type Config = GoldilocksChipConfig<Fr>;

    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        todo!()
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        let arithmetic_chip_config = ArithmeticChipConfig::<Fr>::configure(meta);
        GoldilocksChip::configure(&arithmetic_chip_config)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), halo2_proofs::plonk::Error> {
        let goldilocks_chip_config = config.clone();
        let goldilocks_chip = GoldilocksChip::new(&config);
        goldilocks_chip.load_table(&mut layouter)?;
        layouter.assign_region(
            || "",
            |region| {
                let mut ctx = RegionCtx::new(region, 0);
                let local_constants = assign_quadratic_extensions(
                    &mut ctx,
                    &goldilocks_chip,
                    self.evaluation_vars.local_constants,
                );
                let local_wires = assign_quadratic_extensions(
                    &mut ctx,
                    &goldilocks_chip,
                    self.evaluation_vars.local_wires,
                );
                let public_inputs_hash = assign_hash_values(
                    &mut ctx,
                    &goldilocks_chip,
                    self.evaluation_vars.public_inputs_hash,
                );
                let output = self.gate.eval_unfiltered_constraint(
                    &mut ctx,
                    &goldilocks_chip_config,
                    &local_constants,
                    &local_wires,
                    &public_inputs_hash,
                )?;
                let output_expected =
                    assign_quadratic_extensions(&mut ctx, &goldilocks_chip, &self.output);

                assert_eq!(output.len(), output_expected.len());
                output
                    .iter()
                    .zip(output_expected.iter())
                    .for_each(|(a, b)| {
                        goldilocks_chip
                            .assert_equal(&mut ctx, &a.0[0], &b.0[0])
                            .unwrap();
                        goldilocks_chip
                            .assert_equal(&mut ctx, &a.0[1], &b.0[1])
                            .unwrap();
                    });
                Ok(())
            },
        )?;

        Ok(())
    }
}

pub fn test_custom_gate<PG: Gate<F, D>, HG: CustomGateConstrainer<Fr>>(
    plonky2_gate: PG,
    halo2_gate: HG,
    k: u32,
) {
    let wires = FE::rand_vec(plonky2_gate.num_wires());
    let constants = FE::rand_vec(plonky2_gate.num_constants());
    let public_inputs_hash = HashOut::<F>::rand();
    let evaluation_vars = EvaluationVars::<F, D> {
        local_constants: &constants,
        local_wires: &wires,
        public_inputs_hash: &public_inputs_hash,
    };
    let output: Vec<QuadraticExtension<F>> = plonky2_gate.eval_unfiltered(evaluation_vars);
    let circuit = TestCircuit {
        gate: halo2_gate,
        evaluation_vars,
        output,
    };
    MockProver::run(k, &circuit, vec![vec![]])
        .unwrap()
        .assert_satisfied();

    let srs: ParamsKZG<Bn256> = EvmVerifier::gen_srs(k);
    let pk = EvmVerifier::gen_pk(&srs, &circuit);
    let _proof = EvmVerifier::gen_proof(&srs, &pk, circuit, vec![vec![]]);
}
