use crate::snark::{
    chip::goldilocks_extension_chip::GoldilocksExtensionChip,
    chip::{
        fri_chip::FriVerifierChip,
        goldilocks_chip::{GoldilocksChip, GoldilocksChipConfig},
        transcript_chip::TranscriptChip,
    },
    types::{
        assigned::{
            AssignedExtensionFieldValue, AssignedFriChallenges, AssignedFriProofValues,
            AssignedHashValues, AssignedProofChallenges, AssignedProofValues,
            AssignedProofWithPisValues, AssignedVerificationKeyValues,
        },
        common_data::CommonData,
        fri::FriInstanceInfo,
        proof::ProofValues,
        verification_key::VerificationKeyValues,
        HashValues, MerkleCapValues,
    },
};
use halo2_proofs::plonk::*;
use halo2curves::{goldilocks::fp::Goldilocks, group::ff::PrimeField, FieldExt};
use halo2wrong::RegionCtx;
use halo2wrong_maingate::AssignedValue;
use poseidon::Spec;

pub struct PlonkVerifierChip<F: FieldExt> {
    pub goldilocks_chip_config: GoldilocksChipConfig<F>,
}

impl<F: FieldExt> PlonkVerifierChip<F> {
    pub fn construct(goldilocks_chip_config: &GoldilocksChipConfig<F>) -> Self {
        Self {
            goldilocks_chip_config: goldilocks_chip_config.clone(),
        }
    }

    pub fn goldilocks_chip(&self) -> GoldilocksChip<F> {
        GoldilocksChip::<F>::new(&self.goldilocks_chip_config)
    }

    pub fn assign_proof_with_pis(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        public_inputs: &Vec<Goldilocks>,
        proof: &ProofValues<F, 2>,
    ) -> Result<AssignedProofWithPisValues<F, 2>, Error> {
        let goldilocks_chip = self.goldilocks_chip();

        let public_inputs = public_inputs
            .iter()
            .map(|pi| goldilocks_chip.assign_constant(ctx, *pi))
            .collect::<Result<Vec<AssignedValue<F>>, Error>>()?;
        let proof = ProofValues::assign(&self, ctx, &proof)?;
        Ok(AssignedProofWithPisValues {
            proof,
            public_inputs,
        })
    }

    pub fn assign_verification_key(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        vk: &VerificationKeyValues<F>,
    ) -> Result<AssignedVerificationKeyValues<F>, Error> {
        Ok(AssignedVerificationKeyValues {
            constants_sigmas_cap: MerkleCapValues::assign(&self, ctx, &vk.constants_sigmas_cap)?,
            circuit_digest: HashValues::assign(&self, ctx, &vk.circuit_digest)?,
        })
    }

    pub fn get_public_inputs_hash(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        public_inputs: &Vec<AssignedValue<F>>,
        spec: &Spec<Goldilocks, 12, 11>,
    ) -> Result<AssignedHashValues<F>, Error> {
        let mut transcript_chip =
            TranscriptChip::<F, 12, 11, 8>::new(ctx, &spec, &self.goldilocks_chip_config)?;
        let outputs = transcript_chip.hash(ctx, public_inputs.clone(), 4)?;
        Ok(AssignedHashValues {
            elements: outputs.try_into().unwrap(),
        })
    }

    pub fn get_challenges(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        public_inputs_hash: &AssignedHashValues<F>,
        circuit_digest: &AssignedHashValues<F>,
        common_data: &CommonData<F>,
        assigned_proof: &AssignedProofValues<F, 2>,
        num_challenges: usize,
        spec: &Spec<Goldilocks, 12, 11>,
    ) -> Result<AssignedProofChallenges<F, 2>, Error> {
        let mut transcript_chip =
            TranscriptChip::<F, 12, 11, 8>::new(ctx, &spec, &self.goldilocks_chip_config)?;
        for e in circuit_digest.elements.iter() {
            transcript_chip.write_scalar(ctx, &e)?;
        }

        for e in public_inputs_hash.elements.iter() {
            transcript_chip.write_scalar(ctx, &e)?;
        }

        let AssignedProofValues {
            wires_cap,
            plonk_zs_partial_products_cap,
            quotient_polys_cap,
            openings,
            opening_proof:
                AssignedFriProofValues {
                    commit_phase_merkle_cap_values,
                    final_poly,
                    pow_witness,
                    ..
                },
        } = assigned_proof;
        for hash in wires_cap.0.iter() {
            for e in hash.elements.iter() {
                transcript_chip.write_scalar(ctx, &e)?;
            }
        }
        let plonk_betas = transcript_chip.squeeze(ctx, num_challenges)?;
        let plonk_gammas = transcript_chip.squeeze(ctx, num_challenges)?;

        for hash in plonk_zs_partial_products_cap.0.iter() {
            for e in hash.elements.iter() {
                transcript_chip.write_scalar(ctx, &e)?;
            }
        }
        let plonk_alphas = transcript_chip.squeeze(ctx, num_challenges)?;

        for hash in quotient_polys_cap.0.iter() {
            for e in hash.elements.iter() {
                transcript_chip.write_scalar(ctx, &e)?;
            }
        }
        let plonk_zeta = transcript_chip.squeeze(ctx, 2)?;

        let fri_openings = openings.to_fri_openings();

        for v in fri_openings.batches {
            for ext in v.values {
                transcript_chip.write_extension(ctx, &ext)?;
            }
        }

        // Scaling factor to combine polynomials.
        let fri_alpha =
            AssignedExtensionFieldValue(transcript_chip.squeeze(ctx, 2)?.try_into().unwrap());

        // Recover the random betas used in the FRI reductions.
        let fri_betas = commit_phase_merkle_cap_values
            .iter()
            .map(|cap| {
                transcript_chip.write_cap(ctx, cap)?;
                let fri_beta = transcript_chip.squeeze(ctx, 2)?;
                Ok(AssignedExtensionFieldValue(fri_beta.try_into().unwrap()))
            })
            .collect::<Result<Vec<AssignedExtensionFieldValue<F, 2>>, Error>>()?;

        for ext in final_poly.0.iter() {
            for e in ext.0.iter() {
                transcript_chip.write_scalar(ctx, &e)?;
            }
        }

        transcript_chip.write_scalar(ctx, pow_witness)?;
        let fri_pow_response = transcript_chip.squeeze(ctx, 1)?[0].clone();

        let num_fri_queries = common_data.config.fri_config.num_query_rounds;
        let fri_query_indices = transcript_chip.squeeze(ctx, num_fri_queries)?;

        Ok(AssignedProofChallenges {
            plonk_betas,
            plonk_gammas,
            plonk_alphas,
            plonk_zeta: AssignedExtensionFieldValue(plonk_zeta.try_into().unwrap()),
            fri_challenges: AssignedFriChallenges {
                fri_alpha,
                fri_betas,
                fri_pow_response,
                fri_query_indices,
            },
        })
    }

    pub fn verify_proof_with_challenges(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        proof: &AssignedProofValues<F, 2>,
        public_inputs_hash: &AssignedHashValues<F>,
        challenges: &AssignedProofChallenges<F, 2>,
        vk: &AssignedVerificationKeyValues<F>,
        common_data: &CommonData<F>,
        spec: &Spec<Goldilocks, 12, 11>,
    ) -> Result<(), Error> {
        let goldilocks_extension_chip = GoldilocksExtensionChip::new(&self.goldilocks_chip_config);
        let one = goldilocks_extension_chip.one_extension(ctx)?;
        let local_constants = &proof.openings.constants.clone();
        let local_wires = &proof.openings.wires;
        let local_zs = &proof.openings.plonk_zs;
        let next_zs = &proof.openings.plonk_zs_next;
        let s_sigmas = &proof.openings.plonk_sigmas;
        let partial_products = &proof.openings.partial_products;

        let zeta_pow_deg = goldilocks_extension_chip.exp_power_of_2_extension(
            ctx,
            challenges.plonk_zeta.clone(),
            common_data.degree_bits(),
        )?;
        let vanishing_poly_zeta = self.eval_vanishing_poly(
            ctx,
            &common_data,
            &challenges.plonk_zeta,
            &zeta_pow_deg,
            local_constants,
            local_wires,
            public_inputs_hash,
            local_zs,
            next_zs,
            partial_products,
            s_sigmas,
            &challenges.plonk_betas,
            &challenges.plonk_gammas,
            &challenges.plonk_alphas,
        )?;

        let quotient_polys_zeta = &proof.openings.quotient_polys;
        let z_h_zeta = goldilocks_extension_chip.sub_extension(ctx, &zeta_pow_deg, &one)?;
        for (i, chunk) in quotient_polys_zeta
            .chunks(common_data.quotient_degree_factor)
            .enumerate()
        {
            let recombined_quotient =
                goldilocks_extension_chip.reduce_extension(ctx, &zeta_pow_deg, &chunk.to_vec())?;
            let computed_vanishing_poly =
                goldilocks_extension_chip.mul_extension(ctx, &z_h_zeta, &recombined_quotient)?;
            goldilocks_extension_chip.assert_equal_extension(
                ctx,
                &vanishing_poly_zeta[i],
                &computed_vanishing_poly,
            )?;
        }

        let merkle_caps = &[
            vk.constants_sigmas_cap.clone(),
            proof.wires_cap.clone(),
            proof.plonk_zs_partial_products_cap.clone(),
            proof.quotient_polys_cap.clone(),
        ];

        let g = Goldilocks::multiplicative_generator().pow(&[
            ((halo2curves::goldilocks::fp::MODULUS - 1) / (1 << common_data.degree_bits())).to_le(),
            0,
            0,
            0,
        ]);
        let zeta_next = goldilocks_extension_chip.scalar_mul(ctx, &challenges.plonk_zeta, g)?;
        let fri_instance_info =
            FriInstanceInfo::new(&challenges.plonk_zeta, &zeta_next, common_data);
        let offset = self
            .goldilocks_chip()
            .assign_constant(ctx, Goldilocks::multiplicative_generator())?;
        let fri_chip = FriVerifierChip::construct(
            &self.goldilocks_chip_config,
            spec.clone(),
            &offset,
            common_data.fri_params.clone(),
            merkle_caps.to_vec(),
            challenges.fri_challenges.clone(),
            proof.openings.to_fri_openings(),
            proof.opening_proof.clone(),
            fri_instance_info,
        );
        fri_chip.verify_fri_proof(ctx)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner},
        dev::MockProver,
        halo2curves::bn256::Fr,
        plonk::{Circuit, ConstraintSystem, Error},
    };
    use halo2curves::{goldilocks::fp::Goldilocks, group::ff::PrimeField, FieldExt};
    use halo2wrong::RegionCtx;
    use halo2wrong_maingate::MainGate;
    use itertools::Itertools;
    use plonky2::field::{
        extension::quadratic::QuadraticExtension, goldilocks_field::GoldilocksField,
    };
    use poseidon::Spec;

    use crate::{
        snark::{
            chip::{
                goldilocks_chip::{GoldilocksChip, GoldilocksChipConfig},
                goldilocks_extension_chip::GoldilocksExtensionChip,
            },
            types::{
                self,
                assigned::AssignedExtensionFieldValue,
                common_data::CommonData,
                proof::{ProofValues},
                ExtensionFieldValue, HashValues,
            },
        },
        stark::mock,
    };

    use super::PlonkVerifierChip;

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

    struct ChallengeTestCircuit<
        F: FieldExt,
        const T: usize,
        const T_MINUS_ONE: usize,
        const D: usize,
    > {
        spec: Spec<Goldilocks, T, T_MINUS_ONE>,
        inner_circuit_digest: HashValues<F>,
        common_data: CommonData<F>,
        public_inputs: Vec<Goldilocks>,
        proof: ProofValues<F, 2>,
        num_challenges: usize,
        plonk_betas_expected: Vec<Goldilocks>,
        plonk_gammas_expected: Vec<Goldilocks>,
        plonk_alphas_expected: Vec<Goldilocks>,
        plonk_zeta_expected: ExtensionFieldValue<F, D>,
        lde_bits: usize,
        fri_alpha_expected: ExtensionFieldValue<F, D>,
        fri_betas_expected: Vec<ExtensionFieldValue<F, D>>,
        fri_pow_response_expected: Goldilocks,
        fri_query_indices_expected: Vec<usize>,
    }

    impl Circuit<Fr> for ChallengeTestCircuit<Fr, 12, 11, 2> {
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
            let goldilocks_chip = GoldilocksChip::new(&config.goldilocks_chip_config);
            let goldilocks_extension_chip =
                GoldilocksExtensionChip::new(&config.goldilocks_chip_config);

            layouter.assign_region(
                || "",
                |region| {
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);
                    let plonk_verifier_chip =
                        PlonkVerifierChip::construct(&config.goldilocks_chip_config);
                    let circuit_digest =
                        HashValues::assign(&plonk_verifier_chip, ctx, &self.inner_circuit_digest)?;
                    let proof_with_pis = plonk_verifier_chip.assign_proof_with_pis(
                        ctx,
                        &self.public_inputs,
                        &self.proof,
                    )?;
                    let public_inputs_hash = plonk_verifier_chip.get_public_inputs_hash(
                        ctx,
                        &proof_with_pis.public_inputs,
                        &self.spec,
                    )?;
                    let challenges = plonk_verifier_chip.get_challenges(
                        ctx,
                        &public_inputs_hash,
                        &circuit_digest,
                        &self.common_data,
                        &proof_with_pis.proof,
                        self.num_challenges,
                        &self.spec,
                    )?;

                    let fri_alpha_expected = ExtensionFieldValue::assign(
                        &plonk_verifier_chip,
                        ctx,
                        &self.fri_alpha_expected,
                    )?;
                    goldilocks_extension_chip.assert_equal_extension(
                        ctx,
                        &fri_alpha_expected,
                        &challenges.fri_challenges.fri_alpha,
                    )?;

                    let fri_betas_expected = self
                        .fri_betas_expected
                        .iter()
                        .map(|beta| ExtensionFieldValue::assign(&plonk_verifier_chip, ctx, beta))
                        .collect::<Result<Vec<AssignedExtensionFieldValue<Fr, 2>>, Error>>()?;

                    for (expected, actual) in fri_betas_expected
                        .iter()
                        .zip(challenges.fri_challenges.fri_betas.iter())
                    {
                        goldilocks_extension_chip.assert_equal_extension(ctx, expected, actual)?;
                    }

                    let fri_pow_response_expected =
                        goldilocks_chip.assign_constant(ctx, self.fri_pow_response_expected)?;
                    goldilocks_chip.assert_equal(
                        ctx,
                        &fri_pow_response_expected,
                        &challenges.fri_challenges.fri_pow_response,
                    )?;

                    for (expected, actual) in self
                        .fri_query_indices_expected
                        .iter()
                        .zip(challenges.fri_challenges.fri_query_indices.iter())
                    {
                        let actual_bits = goldilocks_chip
                            .to_bits(ctx, actual, Fr::NUM_BITS as usize)
                            .unwrap()
                            .iter()
                            .take(self.lde_bits)
                            .map(|v| v.clone())
                            .collect_vec();
                        let mask = 1;
                        let mut expected = *expected;
                        let mut expected_bits = vec![];
                        while expected != 0 {
                            expected_bits.push(
                                goldilocks_chip
                                    .assign_constant(ctx, Goldilocks((expected & mask) as u64))?,
                            );
                            expected >>= 1;
                        }
                        println!("actual bits len : {}", actual_bits.len());
                        println!("expected bits len : {}", expected_bits.len());
                        for (actual_bit, expected_bit) in actual_bits.iter().zip(expected_bits) {
                            goldilocks_chip.assert_equal(ctx, actual_bit, &expected_bit)?;
                        }
                    }

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
    fn test_challenge() -> anyhow::Result<()> {
        let (proof, vd, cd) = mock::gen_test_proof()?;
        let spec = Spec::<Goldilocks, 12, 11>::new(8, 22);

        let inner_circuit_digest = HashValues::from(vd.circuit_digest.clone());
        let public_inputs = proof
            .public_inputs
            .iter()
            .map(|pi| types::to_goldilocks(*pi))
            .collect_vec();
        let common_data = CommonData::from(cd.clone());
        let num_challenges = common_data.config.num_challenges;

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

        let fri_alpha_expected = ExtensionFieldValue::from(
            (challenges_expected.fri_challenges.fri_alpha as QuadraticExtension<GoldilocksField>).0,
        );
        let fri_betas_expected = challenges_expected
            .fri_challenges
            .fri_betas
            .iter()
            .map(|&fri_beta| {
                ExtensionFieldValue::from((fri_beta as QuadraticExtension<GoldilocksField>).0)
            })
            .collect();
        let fri_pow_response_expected =
            types::to_goldilocks(challenges_expected.fri_challenges.fri_pow_response);
        let fri_query_indices_expected = challenges_expected.fri_challenges.fri_query_indices;

        let proof = ProofValues::<Fr, 2>::from(proof.proof);

        let circuit: ChallengeTestCircuit<Fr, 12, 11, 2> = ChallengeTestCircuit {
            spec,
            inner_circuit_digest,
            common_data,
            public_inputs,
            proof,
            num_challenges,
            plonk_betas_expected,
            plonk_gammas_expected,
            plonk_alphas_expected,
            plonk_zeta_expected,
            fri_alpha_expected,
            fri_betas_expected,
            fri_pow_response_expected,
            fri_query_indices_expected,
            lde_bits: cd.fri_params.lde_bits(),
        };
        let instance = vec![vec![]];
        let _prover = MockProver::run(19, &circuit, instance).unwrap();
        _prover.assert_satisfied();

        Ok(())
    }
}
