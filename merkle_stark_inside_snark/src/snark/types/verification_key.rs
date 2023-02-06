use crate::snark::types::{HashValues, MerkleCapValues};
use halo2curves::goldilocks::fp::Goldilocks;
use halo2curves::FieldExt;
use plonky2::plonk::{circuit_data::VerifierOnlyCircuitData, config::PoseidonGoldilocksConfig};

#[derive(Debug, Default)]
pub struct VerificationKeyValues<F: FieldExt> {
    pub constants_sigmas_cap: MerkleCapValues<F>,
    pub circuit_digest: HashValues<F>,
}

impl From<VerifierOnlyCircuitData<PoseidonGoldilocksConfig, 2>>
    for VerificationKeyValues<Goldilocks>
{
    fn from(value: VerifierOnlyCircuitData<PoseidonGoldilocksConfig, 2>) -> Self {
        VerificationKeyValues {
            constants_sigmas_cap: MerkleCapValues::from(value.constants_sigmas_cap),
            circuit_digest: HashValues::from(value.circuit_digest),
        }
    }
}
