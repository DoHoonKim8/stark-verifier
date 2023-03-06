use crate::snark::goldilocks_extension_chip::GoldilocksExtensionChip;

use super::CustomGateConstrainer;

/// A gate which takes a single constant parameter and outputs that value.
#[derive(Copy, Clone, Debug)]
pub struct ConstantGateConstrainer {
    pub(crate) num_consts: usize,
}

impl CustomGateConstrainer for ConstantGateConstrainer {
    fn eval_unfiltered_constraint(
        &self,
        ctx: &mut halo2wrong::RegionCtx<'_, halo2curves::goldilocks::fp::Goldilocks>,
        main_gate_config: &halo2wrong_maingate::MainGateConfig,
        local_constants: &[crate::snark::types::assigned::AssignedExtensionFieldValue<
            halo2curves::goldilocks::fp::Goldilocks,
            2,
        >],
        local_wires: &[crate::snark::types::assigned::AssignedExtensionFieldValue<
            halo2curves::goldilocks::fp::Goldilocks,
            2,
        >],
        public_inputs_hash: &crate::snark::types::assigned::AssignedHashValues<
            halo2curves::goldilocks::fp::Goldilocks,
        >,
    ) -> Result<
        Vec<
            crate::snark::types::assigned::AssignedExtensionFieldValue<
                halo2curves::goldilocks::fp::Goldilocks,
                2,
            >,
        >,
        halo2_proofs::plonk::Error,
    > {
        let goldilocks_extension_chip = GoldilocksExtensionChip::new(main_gate_config);
        (0..self.num_consts)
            .map(|i| {
                debug_assert!(i < self.num_consts);
                goldilocks_extension_chip.sub_extension(ctx, &local_constants[i], &local_wires[i])
            })
            .collect()
    }
}
