use crate::plonky2_verifier::{
    bn245_poseidon::plonky2_config::Bn254PoseidonGoldilocksConfig,
    types::{HashValues, MerkleCapValues},
};
use halo2_proofs::halo2curves::ff::PrimeField;
use plonky2::plonk::circuit_data::VerifierOnlyCircuitData;

#[derive(Clone, Debug, Default)]
pub struct VerificationKeyValues<F: PrimeField> {
    pub constants_sigmas_cap: MerkleCapValues<F>,
    pub circuit_digest: HashValues<F>,
}

impl<F: PrimeField> From<VerifierOnlyCircuitData<Bn254PoseidonGoldilocksConfig, 2>>
    for VerificationKeyValues<F>
{
    fn from(value: VerifierOnlyCircuitData<Bn254PoseidonGoldilocksConfig, 2>) -> Self {
        VerificationKeyValues {
            constants_sigmas_cap: MerkleCapValues::from(value.constants_sigmas_cap),
            circuit_digest: HashValues::from(value.circuit_digest),
        }
    }
}
