use std::ops::Range;

use crate::plonky2_verifier::context::RegionCtx;
use halo2_proofs::{halo2curves::ff::PrimeField, plonk::Error};

use crate::plonky2_verifier::{
    chip::goldilocks_chip::GoldilocksChipConfig,
    types::assigned::{AssignedExtensionFieldValue, AssignedHashValues},
};

use super::CustomGateConstrainer;

/// Computes `sum alpha^i c_i` for a vector `c_i` of `num_coeffs` elements of the base field.
#[derive(Debug, Clone)]
pub struct ReducingGateConstrainer {
    pub num_coeffs: usize,
}

impl ReducingGateConstrainer {
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

impl<F: PrimeField> CustomGateConstrainer<F> for ReducingGateConstrainer {
    fn eval_unfiltered_constraint(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        goldilocks_chip_config: &GoldilocksChipConfig<F>,
        _local_constants: &[AssignedExtensionFieldValue<F, 2>],
        local_wires: &[AssignedExtensionFieldValue<F, 2>],
        _public_inputs_hash: &AssignedHashValues<F>,
    ) -> Result<Vec<AssignedExtensionFieldValue<F, 2>>, Error> {
        let goldilocks_extension_algebra_chip =
            self.goldilocks_extension_algebra_chip(goldilocks_chip_config);
        let alpha = self.get_local_ext_algebra(local_wires, Self::wires_alpha());
        let old_acc = self.get_local_ext_algebra(local_wires, Self::wires_old_acc());
        let coeffs = self
            .wires_coeffs()
            .map(|i| local_wires[i].clone())
            .collect::<Vec<_>>();
        let accs = (0..self.num_coeffs)
            .map(|i| self.get_local_ext_algebra(local_wires, self.wires_accs(i)))
            .collect::<Vec<_>>();

        let mut constraints = Vec::with_capacity(self.num_constraints());
        let mut acc = old_acc;
        for i in 0..self.num_coeffs {
            let coeff =
                goldilocks_extension_algebra_chip.convert_to_ext_algebra(ctx, &coeffs[i])?;
            let mut tmp =
                goldilocks_extension_algebra_chip.mul_add_ext_algebra(ctx, &acc, &alpha, &coeff)?;
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

#[cfg(test)]
mod tests {
    use super::ReducingGateConstrainer;
    use crate::plonky2_verifier::chip::plonk::gates::gate_test::test_custom_gate;
    use plonky2::gates::reducing::ReducingGate;

    #[test]
    fn test_reducing_gate() {
        let plonky2_gate = ReducingGate::new(4);
        let halo2_gate = ReducingGateConstrainer {
            num_coeffs: plonky2_gate.num_coeffs,
        };
        test_custom_gate(plonky2_gate, halo2_gate, 17);
    }
}
