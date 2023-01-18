use crate::snark::types::{HashOut, ProofWithPublicInputs};
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::plonk::Error;
use halo2wrong::RegionCtx;
use halo2wrong_maingate::{AssignedValue, MainGateConfig};
use halo2wrong_transcript::HasherChip;
use poseidon::Spec;

pub fn deserialize_proof(proof: String) -> ProofWithPublicInputs {
    serde_json::from_str(&proof).unwrap()
}

pub fn deserialize_public_inputs_hash(public_inputs_hash: String) -> HashOut {
    serde_json::from_str(&public_inputs_hash).unwrap()
}

pub struct TranscriptChip<
    N: FieldExt,
    const NUMBER_OF_LIMBS: usize,
    const BIT_LEN: usize,
    const T: usize,
    const RATE: usize,
> {
    hasher_chip: HasherChip<N, NUMBER_OF_LIMBS, BIT_LEN, T, RATE>,
}

impl<
        N: FieldExt,
        const NUMBER_OF_LIMBS: usize,
        const BIT_LEN: usize,
        const T: usize,
        const RATE: usize,
    > TranscriptChip<N, NUMBER_OF_LIMBS, BIT_LEN, T, RATE>
{
    /// Constructs the transcript chip
    pub fn new(
        ctx: &mut RegionCtx<'_, N>,
        spec: &Spec<N, T, RATE>,
        main_gate_config: &MainGateConfig,
    ) -> Result<Self, Error> {
        let hasher_chip = HasherChip::new(ctx, spec, main_gate_config)?;
        Ok(Self { hasher_chip })
    }

    /// Write scalar to the transcript
    pub fn write_scalar(&mut self, scalar: &AssignedValue<N>) {
        self.hasher_chip.update(&[scalar.clone()]);
    }

    // Constrain squeezing new challenge
    pub fn squeeze(&mut self, ctx: &mut RegionCtx<'_, N>) -> Result<AssignedValue<N>, Error> {
        self.hasher_chip.hash(ctx)
    }
}
