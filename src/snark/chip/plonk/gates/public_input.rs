use std::ops::Range;

use crate::snark::context::RegionCtx;
use halo2_proofs::{halo2curves::ff::PrimeField, plonk::Error};

use crate::snark::{
    chip::goldilocks_chip::GoldilocksChipConfig,
    types::assigned::{AssignedExtensionFieldValue, AssignedHashValues},
};

use super::CustomGateConstrainer;

#[derive(Debug, Clone)]
pub struct PublicInputGateConstrainer;

impl PublicInputGateConstrainer {
    pub fn wires_public_inputs_hash() -> Range<usize> {
        0..4
    }
}

impl<F: PrimeField> CustomGateConstrainer<F> for PublicInputGateConstrainer {
    fn eval_unfiltered_constraint(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        goldilocks_chip_config: &GoldilocksChipConfig<F>,
        _local_constants: &[AssignedExtensionFieldValue<F, 2>],
        local_wires: &[AssignedExtensionFieldValue<F, 2>],
        public_inputs_hash: &AssignedHashValues<F>,
    ) -> Result<Vec<AssignedExtensionFieldValue<F, 2>>, Error> {
        let goldilocks_extension_chip = self.goldilocks_extension_chip(goldilocks_chip_config);
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

#[cfg(test)]
mod tests {
    use super::PublicInputGateConstrainer;
    use crate::snark::chip::plonk::gates::gate_test::test_custom_gate;
    use plonky2::gates::public_input::PublicInputGate;

    #[test]
    fn test_public_input_gate() {
        let plonky2_gate = PublicInputGate;
        let halo2_gate = PublicInputGateConstrainer;
        test_custom_gate(plonky2_gate, halo2_gate, 17);
    }
}
