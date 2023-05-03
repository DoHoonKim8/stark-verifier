use std::ops::Range;

use halo2_proofs::plonk::Error;
use halo2curves::FieldExt;
use halo2wrong::RegionCtx;

use crate::snark::{chip::goldilocks_chip::GoldilocksChipConfig, types::assigned::{AssignedExtensionFieldValue, AssignedHashValues}};

use super::CustomGateConstrainer;

/// Computes `sum alpha^i c_i` for a vector `c_i` of `num_coeffs` elements of the base field.
#[derive(Debug, Clone)]
pub struct ReducingGateConstrainer {
    pub num_coeffs: usize,
}

impl ReducingGateConstrainer {
    pub fn new(num_coeffs: usize) -> Self {
        Self { num_coeffs }
    }

    pub fn max_coeffs_len(num_wires: usize, num_routed_wires: usize) -> usize {
        (num_routed_wires - 3 * 2).min((num_wires - 2 * 2) / (2 + 1))
    }

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
    pub fn wires_coeffs(&self) -> Range<usize> {
        Self::START_COEFFS..Self::START_COEFFS + self.num_coeffs
    }
    fn start_accs(&self) -> usize {
        Self::START_COEFFS + self.num_coeffs
    }
    fn wires_accs(&self, i: usize) -> Range<usize> {
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

impl<F: FieldExt> CustomGateConstrainer<F> for ReducingGateConstrainer {
    fn eval_unfiltered_constraint(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        goldilocks_chip_config: &GoldilocksChipConfig<F>,
        local_constants: &[AssignedExtensionFieldValue<F, 2>],
        local_wires: &[AssignedExtensionFieldValue<F, 2>],
        public_inputs_hash: &AssignedHashValues<F>,
    ) -> Result<Vec<AssignedExtensionFieldValue<F, 2>>, Error> {
        let goldilocks_extension_chip = self.goldilocks_extension_chip(goldilocks_chip_config);
        let alpha = local_wires[Self::wires_alpha()][0].clone();
        let old_acc = local_wires[Self::wires_old_acc()][0].clone();
        let coeffs = self
            .wires_coeffs()
            .map(|i| local_wires[i].clone())
            .collect::<Vec<_>>();
        let accs = (0..self.num_coeffs)
            .map(|i| local_wires[self.wires_accs(i)][0].clone())
            .collect::<Vec<_>>();

        let mut constraints = Vec::with_capacity(self.num_constraints());
        let mut acc = old_acc;
        for i in 0..self.num_coeffs {
            let coeff = coeffs[i].clone();
            let mut tmp = goldilocks_extension_chip.mul_add_extension(ctx, &acc, &alpha, &coeff)?;
            tmp = goldilocks_extension_chip.sub_extension(ctx, &tmp, &accs[i])?;
            constraints.push(tmp);
            acc = accs[i].clone();
        }

        Ok(constraints)
    }
}
