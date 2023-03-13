use halo2curves::goldilocks::fp::Goldilocks;
use halo2wrong_maingate::{AssignedValue, MainGate, MainGateConfig};

use crate::snark::types::{assigned::AssignedFriProofValues, common_data::FriParams};

pub struct FriVerifierChip {
    main_gate_config: MainGateConfig,
    /// Representative `g` of the coset used in FRI, so that LDEs in FRI are done over `gH`.
    offset: AssignedValue<Goldilocks>,
    /// The degree of the purported codeword, measured in bits.
    fri_params: FriParams,
    query_indices: Vec<AssignedValue<Goldilocks>>,
    proof: AssignedFriProofValues<Goldilocks, 2>,
}

impl FriVerifierChip {
    pub fn construct(
        main_gate_config: &MainGateConfig,
        offset: &AssignedValue<Goldilocks>,
        fri_params: FriParams,
        query_indices: Vec<AssignedValue<Goldilocks>>,
        proof: AssignedFriProofValues<Goldilocks, 2>,
    ) -> Self {
        Self {
            main_gate_config: main_gate_config.clone(),
            offset: offset.clone(),
            fri_params,
            query_indices: query_indices.clone(),
            proof: proof,
        }
    }

    fn main_gate(&self) -> MainGate<Goldilocks> {
        MainGate::<Goldilocks>::new(self.main_gate_config.clone())
    }

    fn verify_proof_of_work(&self) {}

    fn verify(&self) {}
}
