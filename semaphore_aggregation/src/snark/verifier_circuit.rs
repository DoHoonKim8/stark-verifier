use crate::snark::types::proof::ProofValues;
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{floor_planner::V1, *},
    halo2curves::bn256::Fr,
    plonk::*,
};
use halo2curves::goldilocks::fp::Goldilocks;
use halo2wrong::RegionCtx;
use halo2wrong_maingate::{AssignedValue, MainGate, MainGateConfig, MainGateInstructions};
use itertools::Itertools;
use poseidon::Spec;
use std::marker::PhantomData;

use super::{
    chip::{
        goldilocks_chip::{GoldilocksChip, GoldilocksChipConfig},
        plonk::plonk_verifier_chip::PlonkVerifierChip,
    },
    types::{
        assigned::{
            AssignedProofValues, AssignedProofWithPisValues, AssignedVerificationKeyValues,
        },
        common_data::CommonData,
        proof::{FriProofValues, OpeningSetValues},
        verification_key::VerificationKeyValues,
        HashValues, MerkleCapValues,
    },
    R_F, R_P, T, T_MINUS_ONE,
};

#[derive(Clone)]
pub struct MainGateWithRangeConfig<F: FieldExt> {
    main_gate_config: MainGateConfig,
    _marker: PhantomData<F>,
}

impl<F: FieldExt> MainGateWithRangeConfig<F> {
    pub fn new(meta: &mut ConstraintSystem<F>) -> Self {
        let main_gate_config = MainGate::<F>::configure(meta);
        MainGateWithRangeConfig {
            main_gate_config,
            _marker: PhantomData,
        }
    }
}

#[derive(Clone)]
pub struct Verifier {
    proof: ProofValues<Fr, 2>,
    instances: Vec<Fr>,
    vk: VerificationKeyValues<Fr>,
    common_data: CommonData<Fr>,
    spec: Spec<Goldilocks, T, T_MINUS_ONE>,
}

impl Verifier {
    pub fn new(
        proof: ProofValues<Fr, 2>,
        instances: Vec<Fr>,
        vk: VerificationKeyValues<Fr>,
        common_data: CommonData<Fr>,
        spec: Spec<Goldilocks, T, T_MINUS_ONE>,
    ) -> Self {
        Self {
            proof,
            instances,
            vk,
            common_data,
            spec,
        }
    }

    fn assign_proof_with_pis(
        &self,
        config: &GoldilocksChipConfig<Fr>,
        mut layouter: impl Layouter<Fr>,
        proof: &ProofValues<Fr, 2>,
        instances: &Vec<Fr>,
    ) -> Result<AssignedProofWithPisValues<Fr, 2>, Error> {
        let public_inputs = layouter.assign_region(
            || "Assign Plonky2 public inputs",
            |region| {
                let ctx = &mut RegionCtx::new(region, 0);
                let goldilocks_chip = GoldilocksChip::new(config);

                let public_inputs = instances
                    .iter()
                    .map(|instance| goldilocks_chip.assign_value(ctx, Value::known(*instance)))
                    .collect::<Result<Vec<AssignedValue<Fr>>, Error>>()?;
                Ok(public_inputs)
            },
        )?;

        let wires_cap =
            MerkleCapValues::assign(config, layouter.namespace(|| ""), &proof.wires_cap)?;
        let plonk_zs_partial_products_cap = MerkleCapValues::assign(
            config,
            layouter.namespace(|| ""),
            &proof.plonk_zs_partial_products_cap,
        )?;
        let quotient_polys_cap =
            MerkleCapValues::assign(config, layouter.namespace(|| ""), &proof.quotient_polys_cap)?;
        let openings =
            OpeningSetValues::assign(config, layouter.namespace(|| ""), &proof.openings)?;
        let opening_proof =
            FriProofValues::assign(config, layouter.namespace(|| ""), &proof.opening_proof)?;
        Ok(AssignedProofWithPisValues {
            proof: AssignedProofValues {
                wires_cap,
                plonk_zs_partial_products_cap,
                quotient_polys_cap,
                openings,
                opening_proof,
            },
            public_inputs,
        })
    }

    pub fn assign_verification_key(
        &self,
        config: &GoldilocksChipConfig<Fr>,
        mut layouter: impl Layouter<Fr>,
        vk: &VerificationKeyValues<Fr>,
    ) -> Result<AssignedVerificationKeyValues<Fr>, Error> {
        Ok(AssignedVerificationKeyValues {
            constants_sigmas_cap: MerkleCapValues::assign(
                config,
                layouter.namespace(|| ""),
                &vk.constants_sigmas_cap,
            )?,
            circuit_digest: HashValues::assign(
                config,
                layouter.namespace(|| ""),
                &vk.circuit_digest,
            )?,
        })
    }
}

impl Circuit<Fr> for Verifier {
    type Config = MainGateWithRangeConfig<Fr>;
    type FloorPlanner = V1;

    fn without_witnesses(&self) -> Self {
        Self {
            proof: self.proof.clone(),
            instances: self.instances.clone(),
            vk: self.vk.clone(),
            common_data: self.common_data.clone(),
            spec: Spec::new(R_F, R_P),
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        MainGateWithRangeConfig::new(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        let main_gate = MainGate::new(config.main_gate_config.clone());
        let goldilocks_chip_config = GoldilocksChip::configure(&config.main_gate_config);
        let assigned_proof_with_pis = self.assign_proof_with_pis(
            &goldilocks_chip_config,
            layouter.namespace(|| "Assign proof and public inputs"),
            &self.proof,
            &self.instances,
        )?;
        let assigned_vk = self.assign_verification_key(
            &goldilocks_chip_config,
            layouter.namespace(|| "Assign verification key"),
            &self.vk,
        )?;
        layouter.assign_region(
            || "Verify proof",
            |region| {
                let ctx = &mut RegionCtx::new(region, 0);
                let plonk_verifier_chip = PlonkVerifierChip::construct(&goldilocks_chip_config);
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
                )
            },
        )?;
        for (row, public_input) in
            (0..self.instances.len()).zip_eq(assigned_proof_with_pis.public_inputs)
        {
            main_gate.expose_public(layouter.namespace(|| ""), public_input, row)?;
        }
        Ok(())
    }
}
