use halo2_proofs::halo2curves::bn256::G1Affine;
use halo2_proofs::plonk::keygen_pk;
use halo2_proofs::plonk::keygen_vk;
use halo2_proofs::plonk::verify_proof;
use halo2_proofs::plonk::ProvingKey;
use halo2_proofs::poly::kzg::commitment::ParamsKZG;
use halo2_proofs::transcript::TranscriptWriterBuffer;
use halo2_proofs::{
    halo2curves::bn256::{Bn256, Fr},
    plonk::{create_proof, Circuit},
};
use halo2_solidity_verifier::encode_calldata;
use halo2_solidity_verifier::BatchOpenScheme::Bdfg21;
use halo2_solidity_verifier::Keccak256Transcript;
use halo2_solidity_verifier::{compile_solidity, Evm, SolidityGenerator};
use rand::RngCore;

pub fn test_contract_size(k: u32, circuit: &impl Circuit<Fr>) {
    let mut rng = rand::thread_rng();
    let param = ParamsKZG::<Bn256>::setup(k, &mut rng);

    let vk = keygen_vk(&param, circuit).unwrap();
    let generator = SolidityGenerator::new(&param, &vk, Bdfg21, 0);
    let (verifier_solidity, _vk_solidity) = generator.render_separately().unwrap();
    let verifier_creation_code = compile_solidity(&verifier_solidity);
    let verifier_creation_code_size = verifier_creation_code.len();
    println!("Verifier creation code size: {verifier_creation_code_size}");
}

pub fn test_verify_on_contract(k: u32, circuit: &(impl Circuit<Fr> + Clone), instance: &[Fr]) {
    let mut rng = rand::thread_rng();
    let param = ParamsKZG::<Bn256>::setup(k, &mut rng);
    let vk = keygen_vk(&param, circuit).unwrap();
    let generator = SolidityGenerator::new(&param, &vk, Bdfg21, instance.len());
    let (verifier_solidity, vk_solidity) = generator.render_separately().unwrap();

    let verifier_creation_code = compile_solidity(&verifier_solidity);
    let verifier_creation_code_size = verifier_creation_code.len();
    println!("Verifier creation code size: {verifier_creation_code_size}");
    let mut evm = Evm::default();
    let verifier_address = evm.create(verifier_creation_code);
    let vk_creation_code = compile_solidity(&vk_solidity);
    let vk_address = evm.create(vk_creation_code);

    let pk = keygen_pk(&param, vk, circuit).unwrap();
    let now = std::time::Instant::now();
    let calldata = {
        let proof = create_proof_checked(&param, &pk, circuit.clone(), &instance, &mut rng);
        encode_calldata(Some(vk_address.into()), &proof, &instance)
    };
    println!("Proof creation time: {:?}", now.elapsed());
    let (gas_cost, output) = evm.call(verifier_address, calldata);
    println!("Gas cost: {}", gas_cost);
    println!("Output: {:?}", output);
}

pub fn create_proof_checked(
    params: &ParamsKZG<Bn256>,
    pk: &ProvingKey<G1Affine>,
    circuit: impl Circuit<Fr>,
    instances: &[Fr],
    mut rng: impl RngCore,
) -> Vec<u8> {
    use halo2_proofs::poly::kzg::{
        multiopen::{ProverSHPLONK, VerifierSHPLONK},
        strategy::SingleStrategy,
    };

    let proof = {
        let mut transcript = Keccak256Transcript::new(Vec::new());
        create_proof::<_, ProverSHPLONK<_>, _, _, _, _>(
            params,
            pk,
            &[circuit],
            &[&[instances]],
            &mut rng,
            &mut transcript,
        )
        .unwrap();
        transcript.finalize()
    };

    let result = {
        let mut transcript = Keccak256Transcript::new(proof.as_slice());
        verify_proof::<_, VerifierSHPLONK<_>, _, _, SingleStrategy<_>>(
            params,
            pk.get_vk(),
            SingleStrategy::new(params),
            &[&[instances]],
            &mut transcript,
        )
    };
    assert!(result.is_ok());
    proof
}
