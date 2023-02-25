use std::ops::Range;

use halo2_proofs::plonk::Error;
use halo2curves::goldilocks::fp::Goldilocks;
use halo2wrong::RegionCtx;

use crate::snark::{
    types::assigned::{AssignedExtensionFieldValue, AssignedHashValues},
    verifier_circuit::Verifier,
};

use super::CustomGateConstrainer;

#[derive(Debug, Clone)]
pub struct PublicInputGateConstrainer;

impl PublicInputGateConstrainer {
    pub fn wires_public_inputs_hash() -> Range<usize> {
        0..4
    }
}

impl CustomGateConstrainer for PublicInputGateConstrainer {
    fn eval_unfiltered_constraint(
        &self,
        verifier: &Verifier,
        ctx: &mut RegionCtx<'_, Goldilocks>,
        main_gate_config: &halo2wrong_maingate::MainGateConfig,
        local_constants: &[AssignedExtensionFieldValue<Goldilocks, 2>],
        local_wires: &[AssignedExtensionFieldValue<Goldilocks, 2>],
        public_inputs_hash: &AssignedHashValues<Goldilocks>,
    ) -> Result<Vec<AssignedExtensionFieldValue<Goldilocks, 2>>, Error> {
        Self::wires_public_inputs_hash()
            .zip(public_inputs_hash.elements.clone())
            .map(|(wire, hash_part)| {
                let hash_part_ext =
                    verifier.convert_to_extension(ctx, main_gate_config, &hash_part)?;
                verifier.sub_extension(ctx, main_gate_config, &local_wires[wire], &hash_part_ext)
            })
            .collect()
    }
}
