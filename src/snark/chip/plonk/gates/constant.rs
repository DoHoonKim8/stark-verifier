use halo2_proofs::halo2curves::ff::PrimeField;

use crate::snark::{
    chip::{
        goldilocks_chip::GoldilocksChipConfig, goldilocks_extension_chip::GoldilocksExtensionChip,
    },
    context::RegionCtx,
};

use super::CustomGateConstrainer;

/// A gate which takes a single constant parameter and outputs that value.
#[derive(Copy, Clone, Debug)]
pub struct ConstantGateConstrainer {
    pub(crate) num_consts: usize,
}

impl<F: PrimeField> CustomGateConstrainer<F> for ConstantGateConstrainer {
    fn eval_unfiltered_constraint(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        main_gate_config: &GoldilocksChipConfig<F>,
        local_constants: &[crate::snark::types::assigned::AssignedExtensionFieldValue<F, 2>],
        local_wires: &[crate::snark::types::assigned::AssignedExtensionFieldValue<F, 2>],
        _public_inputs_hash: &crate::snark::types::assigned::AssignedHashValues<F>,
    ) -> Result<
        Vec<crate::snark::types::assigned::AssignedExtensionFieldValue<F, 2>>,
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

// #[cfg(test)]
// mod tests {
//     use super::ConstantGateConstrainer;
//     use crate::snark::chip::plonk::gates::gate_test::test_custom_gate;
//     use plonky2::gates::constant::ConstantGate;

//     #[test]
//     fn test_constant_gate() {
//         let plonky2_gate = ConstantGate::new(2);
//         let halo2_gate = ConstantGateConstrainer { num_consts: 2 };
//         test_custom_gate(plonky2_gate, halo2_gate, 17);
//     }
// }
