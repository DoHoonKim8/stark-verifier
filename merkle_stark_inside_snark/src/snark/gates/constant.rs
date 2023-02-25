use super::CustomGateConstrainer;

/// A gate which takes a single constant parameter and outputs that value.
#[derive(Copy, Clone, Debug)]
pub struct ConstantGateConstrainer {
    pub(crate) num_consts: usize,
}

impl CustomGateConstrainer for ConstantGateConstrainer {
    fn eval_unfiltered_constraint(
        &self,
        verifier: &crate::snark::verifier_circuit::Verifier,
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
        (0..self.num_consts)
            .map(|i| {
                debug_assert!(i < self.num_consts);
                verifier.sub_extension(ctx, main_gate_config, &local_constants[i], &local_wires[i])
            })
            .collect()
    }
}
