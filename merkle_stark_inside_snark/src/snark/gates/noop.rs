use halo2_proofs::plonk::Error;
use halo2curves::goldilocks::fp::Goldilocks;
use halo2wrong::RegionCtx;

use crate::snark::{
    types::assigned::{AssignedExtensionFieldValue, AssignedHashValues},
    verifier_circuit::Verifier,
};

use super::CustomGateConstrainer;

pub struct NoopGateConstrainer;

impl CustomGateConstrainer for NoopGateConstrainer {
    fn eval_unfiltered_constraint(
        &self,
        _verifier: &Verifier,
        _ctx: &mut RegionCtx<'_, Goldilocks>,
        _main_gate_config: &halo2wrong_maingate::MainGateConfig,
        _local_constants: &[AssignedExtensionFieldValue<Goldilocks, 2>],
        _local_wires: &[AssignedExtensionFieldValue<Goldilocks, 2>],
        _public_inputs_hash: &AssignedHashValues<Goldilocks>,
    ) -> Result<Vec<AssignedExtensionFieldValue<Goldilocks, 2>>, Error> {
        Ok(vec![])
    }
}
