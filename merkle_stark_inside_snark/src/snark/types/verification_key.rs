use crate::snark::types::{HashValues, MerkleCapValues};
use halo2curves::FieldExt;
use plonky2::plonk::{circuit_data::VerifierOnlyCircuitData, config::PoseidonGoldilocksConfig};

#[derive(Clone, Debug, Default)]
pub struct VerificationKeyValues<F: FieldExt> {
    pub constants_sigmas_cap: MerkleCapValues<F>,
    pub circuit_digest: HashValues<F>,
}

impl<F: FieldExt> From<VerifierOnlyCircuitData<PoseidonGoldilocksConfig, 2>>
    for VerificationKeyValues<F>
{
    fn from(value: VerifierOnlyCircuitData<PoseidonGoldilocksConfig, 2>) -> Self {
        VerificationKeyValues {
            constants_sigmas_cap: MerkleCapValues::from(value.constants_sigmas_cap),
            circuit_digest: HashValues::from(value.circuit_digest),
        }
    }
}
