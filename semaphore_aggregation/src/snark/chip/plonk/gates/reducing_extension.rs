use std::ops::Range;

use halo2_proofs::plonk::Error;
use halo2curves::FieldExt;
use halo2wrong::RegionCtx;

use crate::snark::{
    chip::goldilocks_chip::GoldilocksChipConfig,
    types::assigned::{AssignedExtensionFieldValue, AssignedHashValues},
};

use super::CustomGateConstrainer;

/// Computes `sum alpha^i c_i` for a vector `c_i` of `num_coeffs` elements of the extension field.
#[derive(Debug, Clone)]
pub struct ReducingExtensionGateConstrainer {
    pub num_coeffs: usize,
}

impl ReducingExtensionGateConstrainer {
    pub fn wires_output() -> Range<usize> {
        0..2
    }
    pub fn wires_alpha() -> Range<usize> {
        2..2 * 2
    }
    pub fn wires_old_acc() -> Range<usize> {
        2 * 2..3 * 2
    }
    const START_COEFFS: usize = 3 * 2;

    fn wires_coeff(i: usize) -> Range<usize> {
        Self::START_COEFFS + i * 2..Self::START_COEFFS + (i + 1) * 2
    }

    fn start_accs(&self) -> usize {
        Self::START_COEFFS + self.num_coeffs * 2
    }

    fn wires_accs(&self, i: usize) -> Range<usize> {
        debug_assert!(i < self.num_coeffs);
        if i == self.num_coeffs - 1 {
            // The last accumulator is the output.
            return Self::wires_output();
        }
        self.start_accs() + 2 * i..self.start_accs() + 2 * (i + 1)
    }

    fn num_constraints(&self) -> usize {
        2 * self.num_coeffs
    }
}

impl<F: FieldExt> CustomGateConstrainer<F> for ReducingExtensionGateConstrainer {
    fn eval_unfiltered_constraint(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        goldilocks_chip_config: &GoldilocksChipConfig<F>,
        local_constants: &[AssignedExtensionFieldValue<F, 2>],
        local_wires: &[AssignedExtensionFieldValue<F, 2>],
        public_inputs_hash: &AssignedHashValues<F>,
    ) -> Result<Vec<AssignedExtensionFieldValue<F, 2>>, Error> {
        let goldilocks_extension_algebra_chip =
            self.goldilocks_extension_algebra_chip(goldilocks_chip_config);
        let alpha = self.get_local_ext_algebra(local_wires, Self::wires_alpha());
        let old_acc = self.get_local_ext_algebra(local_wires, Self::wires_old_acc());
        let coeffs = (0..self.num_coeffs)
            .map(|i| self.get_local_ext_algebra(local_wires, Self::wires_coeff(i)))
            .collect::<Vec<_>>();
        let accs = (0..self.num_coeffs)
            .map(|i| self.get_local_ext_algebra(local_wires, self.wires_accs(i)))
            .collect::<Vec<_>>();

        let mut constraints = Vec::with_capacity(self.num_constraints());
        let mut acc = old_acc;
        for i in 0..self.num_coeffs {
            let coeff = &coeffs[i];
            let mut tmp =
                goldilocks_extension_algebra_chip.mul_add_ext_algebra(ctx, &acc, &alpha, coeff)?;
            tmp = goldilocks_extension_algebra_chip.sub_ext_algebra(ctx, &tmp, &accs[i])?;
            constraints.push(tmp);
            acc = accs[i].clone();
        }

        Ok(constraints
            .into_iter()
            .flat_map(|alg| alg.to_ext_array())
            .collect())
    }
}
