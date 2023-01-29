use crate::snark::hasher::HasherChip;
use crate::snark::types::{HashOut, ProofWithPublicInputs};
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::plonk::Error;
use halo2wrong::RegionCtx;
use halo2wrong_maingate::{AssignedValue, MainGateConfig};
use poseidon::Spec;

pub fn deserialize_proof(proof: String) -> ProofWithPublicInputs {
    serde_json::from_str(&proof).unwrap()
}

pub fn deserialize_public_inputs_hash(public_inputs_hash: String) -> HashOut {
    serde_json::from_str(&public_inputs_hash).unwrap()
}

pub struct TranscriptChip<N: FieldExt, const T: usize, const RATE: usize> {
    hasher_chip: HasherChip<N, T, RATE>,
}

impl<N: FieldExt, const T: usize, const RATE: usize> TranscriptChip<N, T, RATE> {
    /// Constructs the transcript chip
    pub fn new(
        ctx: &mut RegionCtx<'_, N>,
        spec: &Spec<N, T, RATE>,
        main_gate_config: &MainGateConfig,
    ) -> Result<Self, Error> {
        let hasher_chip = HasherChip::new(ctx, spec, main_gate_config)?;
        Ok(Self { hasher_chip })
    }

    /// Write scalar to the transcript
    pub fn write_scalar(&mut self, scalar: &AssignedValue<N>) {
        self.hasher_chip.update(&[scalar.clone()]);
    }

    /// Constrain squeezing new challenge
    pub fn squeeze(
        &mut self,
        ctx: &mut RegionCtx<'_, N>,
        num_outputs: usize,
    ) -> Result<Vec<AssignedValue<N>>, Error> {
        self.hasher_chip.hash(ctx, num_outputs)
    }
}

#[cfg(test)]
mod tests {
    use crate::snark::transcript::TranscriptChip;
    use crate::stark::mock;
    use halo2_proofs::{
        arithmetic::Field,
        circuit::{Layouter, SimpleFloorPlanner, Value},
        dev::MockProver,
        plonk::{Circuit, ConstraintSystem, Error},
    };
    use halo2curves::{goldilocks::fp::Goldilocks, FieldExt};
    use halo2wrong::RegionCtx;
    use halo2wrong_maingate::{MainGate, MainGateConfig, MainGateInstructions};
    use plonky2::plonk::config::GenericHashOut;
    use poseidon::{Poseidon, Spec};
    use rand::rngs::OsRng;

    #[derive(Clone)]
    struct TestCircuitConfig {
        main_gate_config: MainGateConfig,
    }

    impl TestCircuitConfig {
        fn new<F: FieldExt>(meta: &mut ConstraintSystem<F>) -> Self {
            let main_gate_config = MainGate::configure(meta);
            Self { main_gate_config }
        }
    }

    struct TestCircuit<F: FieldExt, const T: usize, const T_MINUS_ONE: usize> {
        spec: Spec<F, T, T_MINUS_ONE>,
        n: usize,
        num_output: usize,
        inputs: Value<Vec<F>>,
        expected: Value<Vec<F>>,
    }

    impl Circuit<Goldilocks> for TestCircuit<Goldilocks, 12, 11> {
        type Config = TestCircuitConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn configure(meta: &mut ConstraintSystem<Goldilocks>) -> Self::Config {
            TestCircuitConfig::new(meta)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Goldilocks>,
        ) -> Result<(), Error> {
            let main_gate = MainGate::<Goldilocks>::new(config.main_gate_config.clone());

            layouter.assign_region(
                || "",
                |region| {
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);

                    let mut transcript_chip = TranscriptChip::<Goldilocks, 12, 11>::new(
                        ctx,
                        &self.spec,
                        &config.main_gate_config,
                    )?;

                    for e in self.inputs.as_ref().transpose_vec(self.n) {
                        let e = main_gate.assign_value(ctx, e.map(|e| *e))?;
                        transcript_chip.write_scalar(&e);
                    }

                    let challenges = transcript_chip.squeeze(ctx, self.num_output)?;
                    for (challenge, expected) in challenges
                        .iter()
                        .zip(self.expected.as_ref().transpose_vec(self.num_output))
                    {
                        let expected = main_gate.assign_value(ctx, expected.map(|e| *e))?;
                        main_gate.assert_equal(ctx, &challenge, &expected)?;
                    }

                    Ok(())
                },
            )?;

            Ok(())
        }

        fn without_witnesses(&self) -> Self {
            unimplemented!()
        }
    }

    #[test]
    fn test_hasher_chip_against_ref_hasher() {
        let mut ref_hasher = Poseidon::<Goldilocks, 12, 8, 11>::new(8, 22);
        let spec = Spec::<Goldilocks, 12, 11>::new(8, 22);

        let inputs: Vec<Goldilocks> = (0..4).map(|_| Goldilocks::random(OsRng)).collect();
        ref_hasher.update(&inputs[..]);
        let expected = ref_hasher.squeeze(1);

        let circuit = TestCircuit {
            spec,
            n: inputs.len(),
            num_output: 1,
            inputs: Value::known(inputs),
            expected: Value::known(expected),
        };
        let instance = vec![vec![]];
        let _prover = MockProver::run(12, &circuit, instance).unwrap();
        _prover.assert_satisfied()
    }

    #[test]
    fn test_hasher_chip_for_public_inputs() -> anyhow::Result<()> {
        let (proof, _, _) = mock::gen_dummy_proof()?;
        let spec = Spec::<Goldilocks, 12, 11>::new(8, 22);

        let inputs = proof
            .public_inputs
            .iter()
            .map(|f| Goldilocks::from(f.0))
            .collect::<Vec<Goldilocks>>();

        let expected = proof
            .get_public_inputs_hash()
            .to_vec()
            .iter()
            .map(|f| Goldilocks::from(f.0))
            .collect::<Vec<Goldilocks>>();

        let circuit = TestCircuit {
            spec,
            n: inputs.len(),
            num_output: expected.len(),
            inputs: Value::known(inputs),
            expected: Value::known(expected),
        };
        let instance = vec![vec![]];
        let _prover = MockProver::run(12, &circuit, instance).unwrap();
        _prover.assert_satisfied();

        Ok(())
    }
}
