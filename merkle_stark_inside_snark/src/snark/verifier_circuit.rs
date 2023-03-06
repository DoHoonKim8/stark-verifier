use crate::snark::{transcript::TranscriptChip, types::proof::ProofValues};
use halo2_proofs::{arithmetic::FieldExt, circuit::*, plonk::*};
use halo2curves::goldilocks::fp::Goldilocks;
use halo2wrong::RegionCtx;
use halo2wrong_maingate::{AssignedValue, MainGate, MainGateConfig, MainGateInstructions};
use poseidon::Spec;
use std::marker::PhantomData;

use super::{
    goldilocks_extension_chip::GoldilocksExtensionChip,
    types::{
        assigned::{
            AssignedExtensionFieldValue, AssignedFriProofValues, AssignedHashValues,
            AssignedProofChallenges, AssignedProofValues, AssignedProofWithPisValues,
            AssignedVerificationKeyValues,
        },
        common_data::CommonData,
        verification_key::VerificationKeyValues,
        HashValues, MerkleCapValues,
    },
};

#[derive(Clone)]
pub struct VerifierConfig<F: FieldExt> {
    main_gate_config: MainGateConfig,
    _marker: PhantomData<F>,
}

impl<F: FieldExt> VerifierConfig<F> {
    pub fn new(meta: &mut ConstraintSystem<F>) -> Self {
        let main_gate_config = MainGate::<F>::configure(meta);
        VerifierConfig {
            main_gate_config,
            _marker: PhantomData,
        }
    }
}

pub struct Verifier {
    proof: ProofValues<Goldilocks, 2>,
    public_inputs: Vec<Goldilocks>,
    vk: VerificationKeyValues<Goldilocks>,
    common_data: CommonData,
    spec: Spec<Goldilocks, 12, 11>,
}

impl Verifier {
    pub fn new(
        proof: ProofValues<Goldilocks, 2>,
        public_inputs: Vec<Goldilocks>,
        vk: VerificationKeyValues<Goldilocks>,
        common_data: CommonData,
        spec: Spec<Goldilocks, 12, 11>,
    ) -> Verifier {
        Verifier {
            proof,
            public_inputs,
            vk,
            common_data,
            spec,
        }
    }

    pub fn main_gate(&self, main_gate_config: &MainGateConfig) -> MainGate<Goldilocks> {
        MainGate::<Goldilocks>::new(main_gate_config.clone())
    }

    fn assign_proof_with_pis(
        &self,
        ctx: &mut RegionCtx<'_, Goldilocks>,
        main_gate_config: &MainGateConfig,
    ) -> Result<AssignedProofWithPisValues<Goldilocks, 2>, Error> {
        let main_gate = self.main_gate(main_gate_config);

        let public_inputs = self
            .public_inputs
            .iter()
            .map(|pi| main_gate.assign_constant(ctx, *pi))
            .collect::<Result<Vec<AssignedValue<Goldilocks>>, Error>>()?;
        let proof = ProofValues::assign(&self, ctx, main_gate_config, &self.proof)?;
        Ok(AssignedProofWithPisValues {
            proof,
            public_inputs,
        })
    }

    fn assign_verification_key(
        &self,
        ctx: &mut RegionCtx<'_, Goldilocks>,
        main_gate_config: &MainGateConfig,
    ) -> Result<AssignedVerificationKeyValues<Goldilocks>, Error> {
        Ok(AssignedVerificationKeyValues {
            constants_sigmas_cap: MerkleCapValues::assign(
                &self,
                ctx,
                main_gate_config,
                &self.vk.constants_sigmas_cap,
            )?,
            circuit_digest: HashValues::assign(
                &self,
                ctx,
                main_gate_config,
                &self.vk.circuit_digest,
            )?,
        })
    }

    fn get_public_inputs_hash(
        &self,
        ctx: &mut RegionCtx<'_, Goldilocks>,
        main_gate_config: &MainGateConfig,
        public_inputs: &Vec<AssignedValue<Goldilocks>>,
    ) -> Result<AssignedHashValues<Goldilocks>, Error> {
        let mut transcript_chip =
            TranscriptChip::<Goldilocks, 12, 11, 8>::new(ctx, &self.spec, main_gate_config)?;
        let outputs = transcript_chip.hash(ctx, public_inputs.clone(), 4)?;
        Ok(AssignedHashValues {
            elements: outputs.try_into().unwrap(),
        })
    }

    fn get_challenges(
        &self,
        ctx: &mut RegionCtx<'_, Goldilocks>,
        main_gate_config: &MainGateConfig,
        public_inputs_hash: &AssignedHashValues<Goldilocks>,
        circuit_digest: &AssignedHashValues<Goldilocks>,
        assigned_proof: &AssignedProofValues<Goldilocks, 2>,
        num_challenges: usize,
    ) -> Result<AssignedProofChallenges<Goldilocks, 2>, Error> {
        let mut transcript_chip =
            TranscriptChip::<Goldilocks, 12, 11, 8>::new(ctx, &self.spec, main_gate_config)?;

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
        Ok(AssignedProofChallenges {
            plonk_betas,
            plonk_gammas,
            plonk_alphas,
            plonk_zeta: AssignedExtensionFieldValue(plonk_zeta.try_into().unwrap()),
        })
    }

    fn verify_proof_with_challenges(
        &self,
        ctx: &mut RegionCtx<'_, Goldilocks>,
        main_gate_config: &MainGateConfig,
        proof: &AssignedProofValues<Goldilocks, 2>,
        public_inputs_hash: &AssignedHashValues<Goldilocks>,
        challenges: &AssignedProofChallenges<Goldilocks, 2>,
        vk: &AssignedVerificationKeyValues<Goldilocks>,
    ) -> Result<(), Error> {
        let goldilocks_extension_chip = GoldilocksExtensionChip::new(main_gate_config);
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
            self.common_data.degree_bits(),
        )?;
        let vanishing_poly_zeta = self.eval_vanishing_poly(
            ctx,
            main_gate_config,
            &self.common_data,
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
            .chunks(self.common_data.quotient_degree_factor)
            .enumerate()
        {
            let recombined_quotient =
                goldilocks_extension_chip.reduce_arithmetic(ctx, &zeta_pow_deg, &chunk.to_vec())?;
            let computed_vanishing_poly =
                goldilocks_extension_chip.mul_extension(ctx, &z_h_zeta, &recombined_quotient)?;
            goldilocks_extension_chip.assert_equal_extension(
                ctx,
                &vanishing_poly_zeta[i],
                &computed_vanishing_poly,
            )?;
        }
        Ok(())
    }
}

impl Circuit<Goldilocks> for Verifier {
    type Config = VerifierConfig<Goldilocks>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            proof: ProofValues::default(),
            public_inputs: vec![],
            vk: VerificationKeyValues::default(),
            common_data: CommonData::default(),
            spec: Spec::new(8, 22),
        }
    }

    fn configure(meta: &mut ConstraintSystem<Goldilocks>) -> Self::Config {
        VerifierConfig::new(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Goldilocks>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "Plonky2 verifier",
            |region| {
                let offset = 0;
                let ctx = &mut RegionCtx::new(region, offset);

                let assigned_proof_with_pis =
                    self.assign_proof_with_pis(ctx, &config.main_gate_config)?;
                let assigned_vk = self.assign_verification_key(ctx, &config.main_gate_config)?;
                let public_inputs_hash = self.get_public_inputs_hash(
                    ctx,
                    &config.main_gate_config,
                    &assigned_proof_with_pis.public_inputs,
                )?;

                let challenges = self.get_challenges(
                    ctx,
                    &config.main_gate_config,
                    &public_inputs_hash,
                    &assigned_vk.circuit_digest,
                    &assigned_proof_with_pis.proof,
                    self.common_data.config.num_challenges,
                )?;
                self.verify_proof_with_challenges(
                    ctx,
                    &config.main_gate_config,
                    &assigned_proof_with_pis.proof,
                    &public_inputs_hash,
                    &challenges,
                    &assigned_vk,
                )?;
                Ok(())
            },
        )?;

        Ok(())
    }
}
