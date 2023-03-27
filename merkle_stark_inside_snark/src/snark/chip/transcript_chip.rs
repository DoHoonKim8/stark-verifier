use crate::snark::{
    chip::hasher_chip::HasherChip,
    types::assigned::{AssignedExtensionFieldValue, AssignedHashValues, AssignedMerkleCapValues},
};
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::plonk::Error;
use halo2curves::goldilocks::fp::Goldilocks;
use halo2wrong::RegionCtx;
use halo2wrong_maingate::AssignedValue;
use poseidon::Spec;

use super::goldilocks_chip::GoldilocksChipConfig;

pub struct TranscriptChip<N: FieldExt, const T: usize, const T_MINUS_ONE: usize, const RATE: usize>
{
    hasher_chip: HasherChip<N, T, T_MINUS_ONE, RATE>,
}

impl<N: FieldExt, const T: usize, const T_MINUS_ONE: usize, const RATE: usize>
    TranscriptChip<N, T, T_MINUS_ONE, RATE>
{
    /// Constructs the transcript chip
    pub fn new(
        ctx: &mut RegionCtx<'_, N>,
        spec: &Spec<Goldilocks, T, T_MINUS_ONE>,
        goldilocks_chip_config: &GoldilocksChipConfig<N>,
    ) -> Result<Self, Error> {
        let hasher_chip = HasherChip::new(ctx, spec, goldilocks_chip_config)?;
        Ok(Self { hasher_chip })
    }

    /// Write scalar to the transcript
    pub fn write_scalar(
        &mut self,
        ctx: &mut RegionCtx<'_, N>,
        scalar: &AssignedValue<N>,
    ) -> Result<(), Error> {
        self.hasher_chip.update(ctx, scalar)
    }

    pub fn write_extension<const D: usize>(
        &mut self,
        ctx: &mut RegionCtx<'_, N>,
        extension: &AssignedExtensionFieldValue<N, D>,
    ) -> Result<(), Error> {
        for scalar in extension.0.iter() {
            self.write_scalar(ctx, scalar)?;
        }
        Ok(())
    }

    pub fn write_hash(
        &mut self,
        ctx: &mut RegionCtx<'_, N>,
        hash: &AssignedHashValues<N>,
    ) -> Result<(), Error> {
        for scalar in hash.elements.iter() {
            self.write_scalar(ctx, scalar)?;
        }
        Ok(())
    }

    pub fn write_cap(
        &mut self,
        ctx: &mut RegionCtx<'_, N>,
        cap: &AssignedMerkleCapValues<N>,
    ) -> Result<(), Error> {
        for hash in cap.0.iter() {
            self.write_hash(ctx, &hash)?;
        }
        Ok(())
    }

    /// Constrain squeezing new challenge
    pub fn squeeze(
        &mut self,
        ctx: &mut RegionCtx<'_, N>,
        num_outputs: usize,
    ) -> Result<Vec<AssignedValue<N>>, Error> {
        self.hasher_chip.squeeze(ctx, num_outputs)
    }

    /// This function just constraints hash input & output
    pub fn hash(
        &mut self,
        ctx: &mut RegionCtx<'_, N>,
        inputs: Vec<AssignedValue<N>>,
        num_outputs: usize,
    ) -> Result<Vec<AssignedValue<N>>, Error> {
        self.hasher_chip.hash(ctx, inputs, num_outputs)
    }
}

#[cfg(test)]
mod tests {
    use std::marker::PhantomData;

    use crate::snark::chip::goldilocks_chip::{GoldilocksChip, GoldilocksChipConfig};
    use crate::snark::chip::transcript_chip::TranscriptChip;
    use halo2_proofs::{
        arithmetic::Field,
        circuit::{Layouter, SimpleFloorPlanner},
        dev::MockProver,
        plonk::{Circuit, ConstraintSystem, Error},
    };
    use halo2curves::bn256::Fr;
    use halo2curves::{goldilocks::fp::Goldilocks, FieldExt};
    use halo2wrong::RegionCtx;
    use halo2wrong_maingate::MainGate;
    use poseidon::{Poseidon, Spec};
    use rand::rngs::OsRng;

    #[derive(Clone)]
    struct TestCircuitConfig<F: FieldExt> {
        goldilocks_chip_config: GoldilocksChipConfig<F>,
    }

    impl<F: FieldExt> TestCircuitConfig<F> {
        fn new(meta: &mut ConstraintSystem<F>) -> Self {
            let main_gate_config = MainGate::configure(meta);
            let goldilocks_chip_config = GoldilocksChip::configure(&main_gate_config);
            Self {
                goldilocks_chip_config,
            }
        }
    }

    struct TestCircuit<F: FieldExt, const T: usize, const T_MINUS_ONE: usize> {
        spec: Spec<Goldilocks, T, T_MINUS_ONE>,
        n: usize,
        num_output: usize,
        inputs: Vec<Goldilocks>,
        expected: Vec<Goldilocks>,
        _marker: PhantomData<F>,
    }

    impl Circuit<Fr> for TestCircuit<Fr, 12, 11> {
        type Config = TestCircuitConfig<Fr>;
        type FloorPlanner = SimpleFloorPlanner;

        fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
            TestCircuitConfig::new(meta)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fr>,
        ) -> Result<(), Error> {
            let main_gate = GoldilocksChip::new(&config.goldilocks_chip_config);

            layouter.assign_region(
                || "",
                |region| {
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);

                    let mut transcript_chip = TranscriptChip::<Fr, 12, 11, 8>::new(
                        ctx,
                        &self.spec,
                        &config.goldilocks_chip_config,
                    )?;

                    let mut inputs = vec![];
                    for e in self.inputs.iter() {
                        let e = main_gate.assign_constant(ctx, *e)?;
                        inputs.push(e);
                    }

                    let actual = transcript_chip.hash(ctx, inputs, self.num_output)?;
                    for (actual, expected) in actual.iter().zip(self.expected.iter()) {
                        let expected = main_gate.assign_constant(ctx, *expected)?;
                        main_gate.assert_equal(ctx, &actual, &expected)?;
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
            inputs: inputs,
            expected: expected,
            _marker: PhantomData,
        };
        let instance = vec![vec![]];
        let _prover = MockProver::run(12, &circuit, instance).unwrap();
        _prover.assert_satisfied()
    }
}
