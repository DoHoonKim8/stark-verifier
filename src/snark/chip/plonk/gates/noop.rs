use halo2_proofs::plonk::Error;
use halo2curves::FieldExt;
use halo2wrong::RegionCtx;

use crate::snark::{
    chip::goldilocks_chip::GoldilocksChipConfig,
    types::assigned::{AssignedExtensionFieldValue, AssignedHashValues},
};

use super::CustomGateConstrainer;

#[derive(Clone)]
pub struct NoopGateConstrainer;

impl<F: FieldExt> CustomGateConstrainer<F> for NoopGateConstrainer {
    fn eval_unfiltered_constraint(
        &self,
        _ctx: &mut RegionCtx<'_, F>,
        _goldilocks_chip_config: &GoldilocksChipConfig<F>,
        _local_constants: &[AssignedExtensionFieldValue<F, 2>],
        _local_wires: &[AssignedExtensionFieldValue<F, 2>],
        _public_inputs_hash: &AssignedHashValues<F>,
    ) -> Result<Vec<AssignedExtensionFieldValue<F, 2>>, Error> {
        Ok(vec![])
    }
}

#[cfg(test)]
mod tests {
    use super::NoopGateConstrainer;
    use crate::snark::chip::plonk::gates::gate_test::test_custom_gate;
    use plonky2::gates::noop::NoopGate;

    #[test]
    fn test_noop_gate() {
        let plonky2_gate = NoopGate;
        let halo2_gate = NoopGateConstrainer;
        test_custom_gate(plonky2_gate, halo2_gate, 17);
    }
}
