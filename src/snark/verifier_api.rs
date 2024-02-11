use super::bn245_poseidon::plonky2_config::Bn254PoseidonGoldilocksConfig;
use super::types::{
    common_data::CommonData, proof::ProofValues, verification_key::VerificationKeyValues,
};
use super::verifier_circuit::{ProofTuple, Verifier};
use crate::snark::chip::native_chip::test_utils::test_verify_on_contract;
use crate::snark::chip::native_chip::utils::goldilocks_to_fe;
use halo2_proofs::dev::MockProver;
use halo2_proofs::halo2curves::bn256::Fr;
use plonky2::field::goldilocks_field::GoldilocksField;

const DEGREE: u32 = 19;

/// Public API for generating Halo2 proof for Plonky2 verifier circuit
/// feed Plonky2 proof, `VerifierOnlyCircuitData`, `CommonCircuitData`
/// This runs only mock prover for constraint check
pub fn verify_inside_snark_mock(
    proof: ProofTuple<GoldilocksField, Bn254PoseidonGoldilocksConfig, 2>,
) {
    let (proof_with_public_inputs, vd, cd) = proof;
    // proof_with_public_inputs -> ProofValues type
    let proof = ProofValues::<Fr, 2>::from(proof_with_public_inputs.proof);
    let instances = proof_with_public_inputs
        .public_inputs
        .iter()
        .map(|e| goldilocks_to_fe(*e))
        .collect::<Vec<Fr>>();
    // let instances = vec![];
    let vk = VerificationKeyValues::from(vd.clone());
    let common_data = CommonData::from(cd);
    let verifier_circuit = Verifier::new(proof, instances.clone(), vk, common_data);
    let _prover = MockProver::run(DEGREE, &verifier_circuit, vec![instances.clone()]).unwrap();
    _prover.assert_satisfied();
    println!("Mock prover satisfied");
    test_verify_on_contract(DEGREE, &verifier_circuit, &instances);
}

#[cfg(test)]
mod tests {
    use super::verify_inside_snark_mock;
    use crate::snark::{
        bn245_poseidon::plonky2_config::{
            standard_inner_stark_verifier_config, standard_stark_verifier_config,
            Bn254PoseidonGoldilocksConfig,
        },
        verifier_circuit::ProofTuple,
    };
    use plonky2::{
        field::{goldilocks_field::GoldilocksField, types::Field},
        hash::{
            hashing::hash_n_to_hash_no_pad,
            poseidon::{PoseidonHash, PoseidonPermutation},
        },
        iop::witness::{PartialWitness, WitnessWrite},
        plonk::{circuit_builder::CircuitBuilder, config::PoseidonGoldilocksConfig},
    };

    type F = GoldilocksField;
    const D: usize = 2;

    fn generate_proof_tuple() -> ProofTuple<F, Bn254PoseidonGoldilocksConfig, D> {
        let (inner_target, inner_data) = {
            let hash_const =
                hash_n_to_hash_no_pad::<F, PoseidonPermutation>(&[F::from_canonical_u64(42)]);
            let mut builder = CircuitBuilder::<F, D>::new(standard_inner_stark_verifier_config());
            let target = builder.add_virtual_target();
            let expected_hash = builder.constant_hash(hash_const);
            let hash = builder.hash_n_to_hash_no_pad::<PoseidonHash>(vec![target]);
            builder.connect_hashes(hash, expected_hash);
            builder.register_public_inputs(&expected_hash.elements);
            let data = builder.build::<PoseidonGoldilocksConfig>();
            (target, data)
        };

        let mut builder = CircuitBuilder::<F, D>::new(standard_stark_verifier_config());
        let proof_t =
            builder.add_virtual_proof_with_pis::<PoseidonGoldilocksConfig>(&inner_data.common);
        let vd = builder.constant_verifier_data(&inner_data.verifier_only);
        builder.verify_proof::<PoseidonGoldilocksConfig>(&proof_t, &vd, &inner_data.common);
        builder.register_public_inputs(&proof_t.public_inputs);
        let data = builder.build::<Bn254PoseidonGoldilocksConfig>();

        let proof = {
            let mut pw = PartialWitness::new();
            pw.set_target(inner_target, F::from_canonical_usize(42));
            inner_data.prove(pw).unwrap()
        };

        let mut pw = PartialWitness::new();
        pw.set_proof_with_pis_target(&proof_t, &proof);
        let final_proof = data.prove(pw).unwrap();
        let proof: ProofTuple<F, Bn254PoseidonGoldilocksConfig, D> =
            (final_proof, data.verifier_only, data.common);
        proof
    }

    #[test]
    fn test_recursive_halo2_mock() {
        let proof = generate_proof_tuple();
        verify_inside_snark_mock(proof);
    }
}
