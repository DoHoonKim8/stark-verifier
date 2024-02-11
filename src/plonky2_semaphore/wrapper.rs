use std::marker::PhantomData;

use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::witness::{PartialWitness, WitnessWrite},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, VerifierCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
};

// This circuit verifies inner_proof in the circuit.
pub struct WrapperCircuit<F, InnerC, OuterC, const D: usize>
where
    F: RichField + Extendable<D>,
    InnerC: GenericConfig<D, F = F>,
    OuterC: GenericConfig<D, F = F>,
    InnerC::Hasher: AlgebraicHasher<F>,
{
    pub data: CircuitData<F, OuterC, D>,
    pub inner_proof: ProofWithPublicInputsTarget<D>,
    _maker: PhantomData<InnerC>,
}

impl<F, InnerC, OuterC, const D: usize> WrapperCircuit<F, InnerC, OuterC, D>
where
    F: RichField + Extendable<D>,
    InnerC: GenericConfig<D, F = F> + 'static,
    InnerC::Hasher: AlgebraicHasher<F>,
    OuterC: GenericConfig<D, F = F>,
{
    pub fn new(config: CircuitConfig, inner_circuit: &VerifierCircuitData<F, InnerC, D>) -> Self {
        let mut builder = CircuitBuilder::new(config);
        let inner_proof = builder.add_virtual_proof_with_pis::<InnerC>(&inner_circuit.common);
        let vd_target = builder.constant_verifier_data(&inner_circuit.verifier_only);
        builder.verify_proof::<InnerC>(&inner_proof, &vd_target, &inner_circuit.common);
        builder.register_public_inputs(&inner_proof.public_inputs);
        let data = builder.build();
        Self {
            data,
            inner_proof,
            _maker: PhantomData,
        }
    }

    pub fn prove(
        &self,
        inner_proof: &ProofWithPublicInputs<F, InnerC, D>,
    ) -> anyhow::Result<ProofWithPublicInputs<F, OuterC, D>> {
        let mut pw = PartialWitness::new();
        pw.set_proof_with_pis_target(&self.inner_proof, inner_proof);
        self.data.prove(pw)
    }
}
