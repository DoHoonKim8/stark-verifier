use crate::snark::{
    chip::{
        fri_chip::FriVerifierChip,
        goldilocks_chip::{GoldilocksChip, GoldilocksChipConfig},
        transcript_chip::TranscriptChip,
    },
    chip::{goldilocks_extension_chip::GoldilocksExtensionChip, hasher_chip::HasherChip},
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
    RATE, T, T_MINUS_ONE,
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

    pub fn get_public_inputs_hash(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        public_inputs: &Vec<AssignedValue<F>>,
        spec: &Spec<Goldilocks, 12, 11>,
    ) -> Result<AssignedHashValues<F>, Error> {
        let mut hasher_chip =
            HasherChip::<F, T, T_MINUS_ONE, RATE>::new(ctx, &spec, &self.goldilocks_chip_config)?;
        let outputs = hasher_chip.hash(ctx, public_inputs.clone(), 4)?;
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
