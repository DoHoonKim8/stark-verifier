use std::ops::Range;

use halo2_proofs::plonk::Error;
use halo2curves::goldilocks::fp::Goldilocks;
use halo2wrong::RegionCtx;

use crate::snark::types::assigned::{AssignedExtensionFieldValue, AssignedHashValues};

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
        ctx: &mut RegionCtx<'_, Goldilocks>,
        main_gate_config: &halo2wrong_maingate::MainGateConfig,
        local_constants: &[AssignedExtensionFieldValue<Goldilocks, 2>],
        local_wires: &[AssignedExtensionFieldValue<Goldilocks, 2>],
        public_inputs_hash: &AssignedHashValues<Goldilocks>,
    ) -> Result<Vec<AssignedExtensionFieldValue<Goldilocks, 2>>, Error> {
        let goldilocks_extension_chip = self.goldilocks_extension_chip(main_gate_config);
        Self::wires_public_inputs_hash()
            .zip(public_inputs_hash.elements.clone())
            .map(|(wire, hash_part)| {
                let hash_part_ext =
                    goldilocks_extension_chip.convert_to_extension(ctx, &hash_part)?;
                goldilocks_extension_chip.sub_extension(ctx, &local_wires[wire], &hash_part_ext)
            })
            .collect()
    }
}
