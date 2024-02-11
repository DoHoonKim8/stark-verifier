use halo2_proofs::{halo2curves::ff::PrimeField, plonk::Error};
use halo2wrong_maingate::AssignedValue;
use plonky2::{
    field::{goldilocks_field::GoldilocksField, types::Field},
    hash::hashing::SPONGE_WIDTH,
};

use crate::plonky2_verifier::context::RegionCtx;

use super::goldilocks_chip::{GoldilocksChip, GoldilocksChipConfig};

const RATE: usize = 8;

/// `AssignedState` is composed of `T` sized assigned values
#[derive(Debug, Clone)]
pub struct AssignedState<F: PrimeField>(pub(super) [AssignedValue<F>; SPONGE_WIDTH]);

/// `HasherChip` is basically responsible for contraining permutation part of
/// transcript pipeline
#[derive(Debug, Clone)]
pub struct HasherChip<F: PrimeField> {
    state: AssignedState<F>,
    absorbing: Vec<AssignedValue<F>>,
    output_buffer: Vec<AssignedValue<F>>,
    goldilocks_chip_config: GoldilocksChipConfig<F>,
}

impl<F: PrimeField> HasherChip<F> {
    // Constructs new hasher chip with assigned initial state
    pub fn new(
        ctx: &mut RegionCtx<'_, F>,
        goldilocks_chip_config: &GoldilocksChipConfig<F>,
    ) -> Result<Self, Error> {
        let goldilocks_chip = GoldilocksChip::new(goldilocks_chip_config);

        let initial_state = [(); SPONGE_WIDTH]
            .iter()
            .map(|_| goldilocks_chip.assign_constant(ctx, GoldilocksField::ZERO))
            .collect::<Result<Vec<AssignedValue<F>>, Error>>()?;

        Ok(Self {
            state: AssignedState(initial_state.try_into().unwrap()),
            absorbing: vec![],
            output_buffer: vec![],
            goldilocks_chip_config: goldilocks_chip_config.clone(),
        })
    }

    /// Appends field elements to the absorbation line. It won't perform
    /// permutation here
    pub fn update(
        &mut self,
        _ctx: &mut RegionCtx<'_, F>,
        element: &AssignedValue<F>,
    ) -> Result<(), Error> {
        self.output_buffer.clear();
        self.absorbing.push(element.clone());
        Ok(())
    }

    fn absorb_buffered_inputs(&mut self, ctx: &mut RegionCtx<'_, F>) -> Result<(), Error> {
        if self.absorbing.is_empty() {
            return Ok(());
        }
        let buffered_inputs = self.absorbing.clone();
        for input_chunk in buffered_inputs.chunks(RATE) {
            self.duplexing(ctx, input_chunk)?;
        }
        self.absorbing.clear();
        Ok(())
    }

    pub fn squeeze(
        &mut self,
        ctx: &mut RegionCtx<'_, F>,
        num_outputs: usize,
    ) -> Result<Vec<AssignedValue<F>>, Error> {
        let mut output = vec![];
        for _i in 0..num_outputs {
            self.absorb_buffered_inputs(ctx)?;

            if self.output_buffer.is_empty() {
                self.permutation(ctx)?;
                self.output_buffer = self.state.0[0..RATE].to_vec();
            }
            output.push(self.output_buffer.pop().unwrap())
        }
        Ok(output)
    }
}

impl<F: PrimeField> HasherChip<F> {
    /// Construct main gate
    pub fn goldilocks_chip(&self) -> GoldilocksChip<F> {
        GoldilocksChip::new(&self.goldilocks_chip_config)
    }
}

impl<F: PrimeField> HasherChip<F> {
    /// Constrains poseidon permutation while mutating the given state
    pub fn permutation(&mut self, ctx: &mut RegionCtx<'_, F>) -> Result<(), Error> {
        let all_chip = self.goldilocks_chip().all_chip();
        self.state.0 = all_chip.permute(ctx, self.state.0.clone())?;
        Ok(())
    }

    fn duplexing(
        &mut self,
        ctx: &mut RegionCtx<'_, F>,
        input: &[AssignedValue<F>],
    ) -> Result<(), Error> {
        for (word, input) in self.state.0.iter_mut().zip(input.iter()) {
            *word = input.clone();
        }
        self.permutation(ctx)?;

        self.output_buffer.clear();
        self.output_buffer.extend_from_slice(&self.state.0[0..RATE]);
        Ok(())
    }

    pub fn hash(
        &mut self,
        ctx: &mut RegionCtx<'_, F>,
        inputs: Vec<AssignedValue<F>>,
        num_outputs: usize,
    ) -> Result<Vec<AssignedValue<F>>, Error> {
        // Flush the input que
        self.absorbing.clear();

        for chunk in inputs.chunks(RATE) {
            for (word, input) in self.state.0.iter_mut().zip(chunk.iter()) {
                *word = input.clone();
            }
            self.permutation(ctx)?;
        }

        let mut outputs = vec![];
        loop {
            for item in self.state.0.iter().take(RATE) {
                outputs.push(item.clone());
                if outputs.len() == num_outputs {
                    return Ok(outputs);
                }
            }
            self.permutation(ctx)?;
        }
    }

    pub fn permute(
        &mut self,
        ctx: &mut RegionCtx<'_, F>,
        input: Vec<AssignedValue<F>>,
        num_output: usize,
    ) -> Result<Vec<AssignedValue<F>>, Error> {
        for (word, input) in self.state.0.iter_mut().zip(input.iter()) {
            *word = input.clone();
        }
        self.permutation(ctx)?;

        let mut outputs = vec![];
        loop {
            for item in self.state.0.iter().take(RATE) {
                outputs.push(item.clone());
                if outputs.len() == num_output {
                    return Ok(outputs);
                }
            }
            self.permutation(ctx)?;
        }
    }
}

#[cfg(test)]
mod tests {

    use halo2_proofs::{
        circuit::{floor_planner::V1, Layouter, Value},
        dev::MockProver,
        halo2curves::bn256::Fr,
        plonk::{Circuit, ConstraintSystem, Error},
    };
    use plonky2::{
        field::{goldilocks_field::GoldilocksField, types::Sample},
        hash::hashing::PlonkyPermutation,
    };

    use crate::plonky2_verifier::{
        bn245_poseidon::plonky2_config::Bn254PoseidonPermutation,
        chip::{
            goldilocks_chip::{GoldilocksChip, GoldilocksChipConfig},
            native_chip::{
                all_chip::AllChipConfig,
                utils::{fe_to_goldilocks, goldilocks_to_fe},
            },
        },
        context::RegionCtx,
    };

    use super::HasherChip;

    #[derive(Clone, Default)]
    pub struct TestCircuit {
        input: [GoldilocksField; 12],
        expected_output: [GoldilocksField; 12],
    }

    impl Circuit<Fr> for TestCircuit {
        type Config = GoldilocksChipConfig<Fr>;
        type FloorPlanner = V1;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
            let all_chip = AllChipConfig::<Fr>::configure(meta);
            GoldilocksChip::configure(&all_chip)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fr>,
        ) -> Result<(), Error> {
            let goldilocks_chip = GoldilocksChip::new(&config);
            goldilocks_chip.load_table(&mut layouter)?;
            layouter.assign_region(
                || "hasher chip",
                |region| {
                    let ctx = &mut RegionCtx::new(region, 0);

                    let input = self
                        .input
                        .iter()
                        .map(|x| goldilocks_to_fe::<Fr>(*x))
                        .collect::<Vec<_>>();
                    let input_assigned = input
                        .iter()
                        .map(|x| goldilocks_chip.assign_value(ctx, Value::known(*x)))
                        .collect::<Result<Vec<_>, Error>>()?;

                    let mut hasher_chip = HasherChip::<Fr>::new(ctx, &config)?;
                    hasher_chip.state.0 = input_assigned.try_into().unwrap();
                    hasher_chip.permutation(ctx)?;
                    hasher_chip
                        .state
                        .0
                        .iter()
                        .zip(self.expected_output.iter())
                        .for_each(|(x, e)| {
                            x.value().map(|x| assert_eq!(fe_to_goldilocks(*x), *e));
                        });
                    println!("offset: {}", ctx.offset());
                    Ok(())
                },
            )?;
            Ok(())
        }
    }

    #[test]
    fn test_hasher_chip_mock() {
        let input = [(); 12].map(|_| GoldilocksField::rand());
        let expected_output = Bn254PoseidonPermutation::permute(input);

        const DEGREE: u32 = 17;
        let circuit = TestCircuit {
            input,
            expected_output: expected_output.to_vec().try_into().unwrap(),
        };
        let instance: Vec<Fr> = vec![];
        let mock_prover = MockProver::run(DEGREE, &circuit, vec![instance.clone()]).unwrap();
        mock_prover.assert_satisfied();
    }
}
