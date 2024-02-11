use crate::plonky2_verifier::context::RegionCtx;
use halo2_proofs::halo2curves::ff::PrimeField;
use plonky2::field::{goldilocks_field::GoldilocksField, types::Field};
use std::ops::Range;

use crate::plonky2_verifier::{
    chip::goldilocks_chip::GoldilocksChipConfig,
    types::assigned::{AssignedExtensionFieldValue, AssignedHashValues},
};

use super::CustomGateConstrainer;

#[derive(Debug, Clone)]
pub struct BaseSumGateConstrainer {
    pub num_limbs: usize,
}

impl BaseSumGateConstrainer {
    pub const WIRE_SUM: usize = 0;
    pub const START_LIMBS: usize = 1;

    /// Returns the index of the `i`th limb wire.
    pub fn limbs(&self) -> Range<usize> {
        Self::START_LIMBS..Self::START_LIMBS + self.num_limbs
    }
}

impl<F: PrimeField> CustomGateConstrainer<F> for BaseSumGateConstrainer {
    fn eval_unfiltered_constraint(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        goldilocks_chip_config: &GoldilocksChipConfig<F>,
        _local_constants: &[AssignedExtensionFieldValue<F, 2>],
        local_wires: &[AssignedExtensionFieldValue<F, 2>],
        _public_inputs_hash: &AssignedHashValues<F>,
    ) -> Result<Vec<AssignedExtensionFieldValue<F, 2>>, halo2_proofs::plonk::Error> {
        let goldilocks_extension_chip = self.goldilocks_extension_chip(goldilocks_chip_config);
        let base = goldilocks_extension_chip.two_extension(ctx)?;
        let sum = &local_wires[Self::WIRE_SUM];
        let limbs = local_wires[self.limbs()].to_vec();
        let computed_sum = goldilocks_extension_chip.reduce_extension(ctx, &base, &limbs)?;
        let mut constraints =
            vec![goldilocks_extension_chip.sub_extension(ctx, &computed_sum, sum)?];
        for limb in limbs {
            constraints.push({
                let mut acc = goldilocks_extension_chip.one_extension(ctx)?;
                (0..2).for_each(|i| {
                    // We update our accumulator as:
                    // acc' = acc (x - i)
                    //      = acc x + (-i) acc
                    // Since -i is constant, we can do this in one arithmetic_extension call.
                    let neg_i = -GoldilocksField::from_canonical_u64(i as u64);
                    acc = goldilocks_extension_chip
                        .arithmetic_extension(ctx, GoldilocksField::ONE, neg_i, &acc, &limb, &acc)
                        .unwrap();
                });
                acc
            });
        }
        Ok(constraints)
    }
}

#[cfg(test)]
mod tests {
    use super::BaseSumGateConstrainer;
    use crate::plonky2_verifier::chip::plonk::gates::gate_test::test_custom_gate;
    use plonky2::{
        field::goldilocks_field::GoldilocksField, gates::base_sum::BaseSumGate,
        plonk::circuit_data::CircuitConfig,
    };

    type F = GoldilocksField;

    #[test]
    fn test_base_sum_gate() {
        let plonky2_gate =
            BaseSumGate::<2>::new_from_config::<F>(&CircuitConfig::standard_recursion_config());
        let halo2_gate = BaseSumGateConstrainer {
            num_limbs: plonky2_gate.num_limbs,
        };
        test_custom_gate(plonky2_gate, halo2_gate, 17);
    }
}
