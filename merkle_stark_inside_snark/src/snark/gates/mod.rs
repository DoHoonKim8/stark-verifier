use std::ops::Range;

use halo2_proofs::{arithmetic::Field, plonk::Error};
use halo2curves::goldilocks::fp::Goldilocks;
use halo2wrong::RegionCtx;
use halo2wrong_maingate::MainGateConfig;

use super::{types::assigned::AssignedExtensionFieldValue, verifier_circuit::Verifier};

pub mod arithmetic_extension;

/// Represents Plonky2's cutom gate. Evaluate gate constraint in `plonk_zeta` inside halo2 circuit.
pub trait CustomGate {
    fn evaluate_unfiltered_constraint(
        &self,
        verifier: &Verifier,
        ctx: &mut RegionCtx<'_, Goldilocks>,
        main_gate_config: &MainGateConfig,
        local_constants: &[AssignedExtensionFieldValue<Goldilocks, 2>],
        local_wires: &[AssignedExtensionFieldValue<Goldilocks, 2>],
    ) -> Result<Vec<AssignedExtensionFieldValue<Goldilocks, 2>>, Error>;

    /// In Plonky2, each custom gate's constraint is multiplied by filtering polynomial
    /// `j`th gate's constraint is filtered by f_j(x) = \prod_{k=0, k \neq j}^{n-1}(f(x) - k) where
    /// f(g^i) = j if jth gate is used in ith row
    fn evaluate_filtered_constraint(
        &self,
        verifier: &Verifier,
        ctx: &mut RegionCtx<'_, Goldilocks>,
        main_gate_config: &MainGateConfig,
        local_constants: &[AssignedExtensionFieldValue<Goldilocks, 2>],
        local_wires: &[AssignedExtensionFieldValue<Goldilocks, 2>],
        row: usize,
        selector_index: usize,
        group_range: Range<usize>,
        combined_gate_constraints: &mut [AssignedExtensionFieldValue<Goldilocks, 2>],
    ) -> Result<(), Error> {
        // f(\zeta)
        let f_zeta = local_constants[selector_index];
        // \prod_{k=0, k \neq j}^{n-1}(f(\zeta) - k)
        let terms = group_range
            .filter(|&i| i != row)
            .map(|i| {
                let k = verifier.constant_extension(
                    ctx,
                    main_gate_config,
                    &[Goldilocks::from(i as u64), Goldilocks::zero()],
                )?;
                verifier.sub_extension(ctx, main_gate_config, &f_zeta, &k)
            })
            .collect::<Result<Vec<AssignedExtensionFieldValue<Goldilocks, 2>>, Error>>()?;
        let filter = verifier.mul_many_extension(ctx, main_gate_config, terms)?;

        let gate_constraints = self.evaluate_unfiltered_constraint(
            verifier,
            ctx,
            main_gate_config,
            local_constants,
            local_wires,
        )?;
        for (acc, c) in combined_gate_constraints.iter_mut().zip(gate_constraints) {
            *acc = verifier.mul_add_extension(ctx, main_gate_config, &filter, &c, acc)?;
        }
        Ok(())
    }
}
