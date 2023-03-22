use crate::snark::{
    chip::hasher_chip::HasherChip,
    types::assigned::{AssignedExtensionFieldValue, AssignedHashValues, AssignedMerkleCapValues},
};
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::plonk::Error;
use halo2curves::goldilocks::fp::Goldilocks;
use halo2wrong::RegionCtx;
use halo2wrong_maingate::{AssignedValue, MainGateConfig};
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
    use crate::snark::types::{self, ExtensionFieldValue, HashValues, MerkleCapValues};
    use crate::stark::mock;
    use halo2_proofs::{
        arithmetic::Field,
        circuit::{Layouter, SimpleFloorPlanner, Value},
        dev::MockProver,
        plonk::{Circuit, ConstraintSystem, Error},
    };
    use halo2curves::bn256::Fr;
    use halo2curves::{goldilocks::fp::Goldilocks, FieldExt};
    use halo2wrong::RegionCtx;
    use halo2wrong_maingate::{MainGate, MainGateConfig, MainGateInstructions};
    use plonky2::field::extension::quadratic::QuadraticExtension;
    use plonky2::field::goldilocks_field::GoldilocksField;
    use plonky2::plonk::config::GenericHashOut;
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

    // #[test]
    // fn test_hasher_chip_for_public_inputs_hash() -> anyhow::Result<()> {
    //     let (proof, _, _) = mock::gen_dummy_proof()?;
    //     let spec = Spec::<Goldilocks, 12, 11>::new(8, 22);

    //     let inputs = proof
    //         .public_inputs
    //         .iter()
    //         .map(|f| Goldilocks::from(f.0))
    //         .collect::<Vec<Goldilocks>>();

    //     let expected = proof
    //         .get_public_inputs_hash()
    //         .to_vec()
    //         .iter()
    //         .map(|f| Goldilocks::from(f.0))
    //         .collect::<Vec<Goldilocks>>();

    //     let circuit = TestCircuit {
    //         spec,
    //         n: inputs.len(),
    //         num_output: expected.len(),
    //         inputs: inputs,
    //         expected: expected,
    //         _marker: PhantomData,
    //     };
    //     let instance = vec![vec![]];
    //     let _prover = MockProver::run(12, &circuit, instance).unwrap();
    //     _prover.assert_satisfied();

    //     Ok(())
    // }

    struct PlonkChallengeTestCircuit<
        F: FieldExt,
        const T: usize,
        const T_MINUS_ONE: usize,
        const D: usize,
    > {
        spec: Spec<Goldilocks, T, T_MINUS_ONE>,
        inner_circuit_digest: HashValues<F>,
        public_inputs_hash: HashValues<F>,
        wires_cap: MerkleCapValues<F>,
        num_challenges: usize,
        plonk_zs_partial_products_cap: MerkleCapValues<F>,
        quotient_polys_cap: MerkleCapValues<F>,
        // openings: OpeningSetValues<F, D>,
        // opening_proof: FriProofValues<F, D>,
        plonk_betas_expected: Vec<Goldilocks>,
        plonk_gammas_expected: Vec<Goldilocks>,
        plonk_alphas_expected: Vec<Goldilocks>,
        plonk_zeta_expected: ExtensionFieldValue<F, D>,
        // fri_alpha_expected: ExtensionFieldValue<F, D>,
        // fri_betas_expected: Vec<ExtensionFieldValue<F, D>>,
        // fri_pow_response: F,
        // fri_query_indices: Value<Vec<usize>>,
    }

    impl Circuit<Fr> for PlonkChallengeTestCircuit<Fr, 12, 11, 2> {
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

                    for e in self.inner_circuit_digest.elements.iter() {
                        let e = main_gate.assign_constant(ctx, *e)?;
                        transcript_chip.write_scalar(ctx, &e)?;
                    }

                    for e in self.public_inputs_hash.elements.iter() {
                        let e = main_gate.assign_constant(ctx, *e)?;
                        transcript_chip.write_scalar(ctx, &e)?;
                    }

                    for hash in self.wires_cap.0.iter() {
                        for e in hash.elements.iter() {
                            let e = main_gate.assign_constant(ctx, *e)?;
                            transcript_chip.write_scalar(ctx, &e)?;
                        }
                    }
                    let plonk_betas = transcript_chip.squeeze(ctx, self.num_challenges)?;
                    let plonk_gammas = transcript_chip.squeeze(ctx, self.num_challenges)?;

                    for (actual, expected) in
                        plonk_betas.iter().zip(self.plonk_betas_expected.iter())
                    {
                        let expected = main_gate.assign_constant(ctx, *expected)?;
                        main_gate.assert_equal(ctx, actual, &expected)?;
                    }

                    // for (actual, expected) in plonk_gammas.iter().zip(
                    //     self.plonk_gammas_expected.iter(),
                    // ) {
                    //     let expected = main_gate.assign_constant(ctx, *expected)?;
                    //     main_gate.assert_equal(ctx, actual, &expected)?;
                    // }

                    // for hash in self.plonk_zs_partial_products_cap.0.iter() {
                    //     for e in hash.elements.iter() {
                    //         let e = main_gate.assign_constant(ctx, *e)?;
                    //         transcript_chip.write_scalar(ctx, &e)?;
                    //     }
                    // }
                    // let plonk_alphas = transcript_chip.squeeze(ctx, self.num_challenges)?;

                    // for (actual, expected) in plonk_alphas.iter().zip(
                    //     self.plonk_alphas_expected.iter(),
                    // ) {
                    //     let expected = main_gate.assign_constant(ctx, *expected)?;
                    //     main_gate.assert_equal(ctx, actual, &expected)?;
                    // }

                    // for hash in self.quotient_polys_cap.0.iter() {
                    //     for e in hash.elements.iter() {
                    //         let e = main_gate.assign_constant(ctx, *e)?;
                    //         transcript_chip.write_scalar(ctx, &e)?;
                    //     }
                    // }
                    // let plonk_zeta = transcript_chip.squeeze(ctx, 2)?;

                    // for (actual, expected) in
                    //     plonk_zeta.iter().zip(self.plonk_zeta_expected.elements.iter())
                    // {
                    //     let expected = main_gate.assign_constant(ctx, *expected)?;
                    //     main_gate.assert_equal(ctx, actual, &expected)?;
                    // }

                    Ok(())
                },
            )?;

            Ok(())
        }

        fn without_witnesses(&self) -> Self {
            todo!()
        }
    }

    #[test]
    fn test_hasher_chip_for_challenges() -> anyhow::Result<()> {
        let (proof, vd, cd) = mock::gen_dummy_proof()?;
        let spec = Spec::<Goldilocks, 12, 11>::new(8, 22);

        let inner_circuit_digest = HashValues::from(vd.circuit_digest.clone());
        let public_inputs_hash = HashValues::from(proof.get_public_inputs_hash().clone());
        let wires_cap = MerkleCapValues::from(proof.proof.wires_cap.clone());
        let num_challenges = cd.config.num_challenges;
        let plonk_zs_partial_products_cap =
            MerkleCapValues::from(proof.proof.plonk_zs_partial_products_cap.clone());
        let quotient_polys_cap = MerkleCapValues::from(proof.proof.quotient_polys_cap.clone());

        let challenges_expected =
            proof.get_challenges(proof.get_public_inputs_hash(), &vd.circuit_digest, &cd)?;
        let plonk_betas_expected = challenges_expected
            .plonk_betas
            .iter()
            .map(|e| types::to_goldilocks(*e))
            .collect::<Vec<Goldilocks>>();
        let plonk_gammas_expected = challenges_expected
            .plonk_gammas
            .iter()
            .map(|e| types::to_goldilocks(*e))
            .collect::<Vec<Goldilocks>>();
        let plonk_alphas_expected = challenges_expected
            .plonk_alphas
            .iter()
            .map(|e| types::to_goldilocks(*e))
            .collect::<Vec<Goldilocks>>();

        let plonk_zeta_expected = ExtensionFieldValue::from(
            (challenges_expected.plonk_zeta as QuadraticExtension<GoldilocksField>).0,
        );

        let circuit: PlonkChallengeTestCircuit<Fr, 12, 11, 2> = PlonkChallengeTestCircuit {
            spec,
            inner_circuit_digest,
            public_inputs_hash,
            wires_cap,
            num_challenges,
            plonk_zs_partial_products_cap,
            quotient_polys_cap,
            plonk_betas_expected,
            plonk_gammas_expected,
            plonk_alphas_expected,
            plonk_zeta_expected,
        };
        let instance = vec![vec![]];
        let _prover = MockProver::run(15, &circuit, instance).unwrap();
        _prover.assert_satisfied();

        Ok(())
    }
}
