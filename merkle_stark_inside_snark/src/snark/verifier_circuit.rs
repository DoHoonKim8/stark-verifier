use crate::snark::types::proof::ProofValues;
use halo2_proofs::{arithmetic::FieldExt, circuit::*, halo2curves::bn256::Fr, plonk::*};
use halo2curves::goldilocks::fp::Goldilocks;
use halo2wrong::RegionCtx;
use halo2wrong_maingate::{MainGate, MainGateConfig};
use poseidon::Spec;
use std::marker::PhantomData;

use super::{
    chip::{goldilocks_chip::GoldilocksChip, plonk::plonk_verifier_chip::PlonkVerifierChip},
    types::{common_data::CommonData, verification_key::VerificationKeyValues},
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

#[derive(Clone)]
pub struct Verifier {
    proof: ProofValues<Fr, 2>,
    public_inputs: Vec<Goldilocks>,
    vk: VerificationKeyValues<Fr>,
    common_data: CommonData<Fr>,
    spec: Spec<Goldilocks, 12, 11>,
}

impl Verifier {
    pub fn new(
        proof: ProofValues<Fr, 2>,
        public_inputs: Vec<Goldilocks>,
        vk: VerificationKeyValues<Fr>,
        common_data: CommonData<Fr>,
        spec: Spec<Goldilocks, 12, 11>,
    ) -> Self {
        Self {
            proof,
            public_inputs,
            vk,
            common_data,
            spec,
        }
    }
}

impl Circuit<Fr> for Verifier {
    type Config = VerifierConfig<Fr>;
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

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        VerifierConfig::new(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "stark_verifier",
            |region| {
                let offset = 0;
                let ctx = &mut RegionCtx::new(region, offset);
                let goldilocks_chip_config = GoldilocksChip::configure(&config.main_gate_config);
                let plonk_verifier_chip = PlonkVerifierChip::construct(&goldilocks_chip_config);

                let assigned_proof_with_pis = plonk_verifier_chip.assign_proof_with_pis(
                    ctx,
                    &self.public_inputs,
                    &self.proof,
                )?;
                let assigned_vk = plonk_verifier_chip.assign_verification_key(ctx, &self.vk)?;

                let public_inputs_hash = plonk_verifier_chip.get_public_inputs_hash(
                    ctx,
                    &assigned_proof_with_pis.public_inputs,
                    &self.spec,
                )?;

                let challenges = plonk_verifier_chip.get_challenges(
                    ctx,
                    &public_inputs_hash,
                    &assigned_vk.circuit_digest,
                    &self.common_data,
                    &assigned_proof_with_pis.proof,
                    self.common_data.config.num_challenges,
                    &self.spec,
                )?;
                plonk_verifier_chip.verify_proof_with_challenges(
                    ctx,
                    &assigned_proof_with_pis.proof,
                    &public_inputs_hash,
                    &challenges,
                    &assigned_vk,
                    &self.common_data,
                    &self.spec,
                )?;
                Ok(())
            },
        )?;

        Ok(())
    }
}
