use std::fs;

use halo2_proofs::poly::commitment::Verifier;
use halo2curves::goldilocks::fp::Goldilocks;
use plonky2::{
    field::{goldilocks_field::GoldilocksField, extension::Extendable},
    plonk::{
        circuit_data::{CircuitData, CommonCircuitData, VerifierOnlyCircuitData},
        config::{GenericConfig, PoseidonGoldilocksConfig},
        proof::ProofWithPublicInputs,
    }, impl_gate_serializer, hash::hash_types::RichField, util::serialization::GateSerializer, gates::{reducing::ReducingGate, reducing_extension::ReducingExtensionGate, random_access::RandomAccessGate, public_input::PublicInputGate, poseidon::PoseidonGate, poseidon_mds::PoseidonMdsGate, noop::NoopGate, multiplication_extension::MulExtensionGate, lookup_table::LookupTableGate, lookup::LookupGate, exponentiation::ExponentiationGate, coset_interpolation::CosetInterpolationGate, constant::ConstantGate, base_sum::BaseSumGate, arithmetic_extension::ArithmeticExtensionGate, arithmetic_base::ArithmeticGate},
};
use plonky2::read_gate_impl;
use plonky2::get_gate_tag_impl;
use semaphore_aggregation::snark::{types::common_data, verifier_api::{verify_inside_snark_mock, verify_inside_snark}};
use plonky2_u32::gates::{
    add_many_u32::U32AddManyGate,
    arithmetic_u32::{U32ArithmeticGate, U32ArithmeticGenerator},
    comparison::{ComparisonGate, ComparisonGenerator},
    range_check_u32::U32RangeCheckGate,
    subtraction_u32::U32SubtractionGate,
};

fn main() {
    let proof = get_proof();
    let verifier_data = get_verifier_data();
    let common_data = get_common_data();

    verify_inside_snark((proof, verifier_data, common_data));
    println!("Hello, world!");
}

fn get_proof() -> ProofWithPublicInputs<GoldilocksField, PoseidonGoldilocksConfig, 2> {
    let bytes = fs::read("final_proof").unwrap();
    let common_data = get_common_data();
    ProofWithPublicInputs::from_bytes(bytes, &common_data).unwrap()
}

fn get_common_data() -> CommonCircuitData<GoldilocksField, 2> {
    let bytes: Vec<u8> = fs::read("common_data").unwrap();
    let gate_serializer = DendrETHGateSerializer;
    CommonCircuitData::from_bytes(bytes, &gate_serializer).unwrap()
}

fn get_verifier_data() -> VerifierOnlyCircuitData<PoseidonGoldilocksConfig, 2> {
    let bytes: Vec<u8> = fs::read("verifier_data").unwrap();

    VerifierOnlyCircuitData::<PoseidonGoldilocksConfig, 2>::from_bytes(bytes).unwrap()
}

pub struct DendrETHGateSerializer;

impl<F: RichField + Extendable<D>, const D: usize> GateSerializer<F, D> for DendrETHGateSerializer {
    impl_gate_serializer! {
        DendrETHGateSerializer,
        ArithmeticGate,
        ArithmeticExtensionGate<D>,
        BaseSumGate<2>,
        ConstantGate,
        CosetInterpolationGate<F, D>,
        ExponentiationGate<F, D>,
        LookupGate,
        LookupTableGate,
        MulExtensionGate<D>,
        NoopGate,
        PoseidonMdsGate<F, D>,
        PoseidonGate<F, D>,
        PublicInputGate,
        RandomAccessGate<F, D>,
        ReducingExtensionGate<D>,
        ReducingGate<D>,
        U32AddManyGate<F, D>,
        U32ArithmeticGate<F, D>,
        U32SubtractionGate<F, D>,
        ComparisonGate<F, D>,
        U32RangeCheckGate<F, D>
    }
}
