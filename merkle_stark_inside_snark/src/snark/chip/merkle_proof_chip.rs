use halo2_proofs::plonk::Error;
use halo2curves::goldilocks::fp::Goldilocks;
use halo2wrong::RegionCtx;
use halo2wrong_maingate::{AssignedValue, MainGate, MainGateConfig, MainGateInstructions};
use itertools::Itertools;
use poseidon::Spec;

use crate::snark::types::assigned::{AssignedMerkleCapValues, AssignedMerkleProofValues};

use super::{hasher_chip::HasherChip, vector_chip::VectorChip};

pub struct MerkleProofChip {
    main_gate_config: MainGateConfig,
    spec: Spec<Goldilocks, 12, 11>,
}

impl MerkleProofChip {
    pub fn new(main_gate_config: &MainGateConfig, spec: Spec<Goldilocks, 12, 11>) -> Self {
        Self {
            main_gate_config: main_gate_config.clone(),
            spec,
        }
    }

    fn main_gate(&self) -> MainGate<Goldilocks> {
        MainGate::new(self.main_gate_config.clone())
    }

    fn hasher(
        &self,
        ctx: &mut RegionCtx<'_, Goldilocks>,
    ) -> Result<HasherChip<Goldilocks, 12, 11, 8>, Error> {
        HasherChip::new(ctx, &self.spec, &self.main_gate_config)
    }

    pub fn verify_merkle_proof_to_cap_with_cap_index(
        &self,
        ctx: &mut RegionCtx<'_, Goldilocks>,
        leaf_data: &Vec<AssignedValue<Goldilocks>>,
        leaf_index_bits: &[AssignedValue<Goldilocks>],
        cap_index: &AssignedValue<Goldilocks>,
        merkle_cap: &AssignedMerkleCapValues<Goldilocks>,
        proof: &AssignedMerkleProofValues<Goldilocks>,
    ) -> Result<(), Error> {
        let mut hasher = self.hasher(ctx)?;
        let main_gate = self.main_gate();

        let mut state = hasher.hash(ctx, leaf_data.clone(), 4)?;

        for (bit, sibling) in leaf_index_bits.iter().zip(proof.siblings.iter()) {
            let mut inputs = vec![];
            for i in 0..4 {
                let left = main_gate.select(ctx, &state[i], &sibling.elements[i], bit)?;
                inputs.push(left);
            }

            for i in 0..4 {
                let right = main_gate.select(ctx, &sibling.elements[i], &state[i], bit)?;
                inputs.push(right);
            }
            state = hasher.hash(ctx, inputs, 4)?;
        }

        for i in 0..4 {
            let vector_chip = VectorChip::new(
                &self.main_gate_config,
                merkle_cap
                    .0
                    .iter()
                    .map(|hash| hash.elements[i].clone())
                    .collect_vec(),
            );
            let cap_i = vector_chip.access(ctx, &cap_index)?;
            main_gate.assert_equal(ctx, &cap_i, &state[i])?;
        }

        Ok(())
    }
}
