use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, VerifierCircuitData, VerifierCircuitTarget};
use plonky2::plonk::config::PoseidonGoldilocksConfig;
use plonky2::plonk::proof::ProofWithPublicInputs;

use super::access_set::AccessSet;
use super::signal::{Digest, PlonkyProof, Signal, C, F};

type InnerC = PoseidonGoldilocksConfig;

impl AccessSet {
    pub fn aggregate_signals(
        &self,
        topic0: Digest,
        signal0: Signal,
        topic1: Digest,
        signal1: Signal,
        verifier_data: &VerifierCircuitData<F, C, 2>,
    ) -> (Digest, Digest, PlonkyProof) {
        let config = CircuitConfig::standard_recursion_zk_config();
        let mut builder = CircuitBuilder::new(config);
        let mut pw = PartialWitness::new();

        let public_inputs0: Vec<F> = self
            .0
            .cap
            .0
            .iter()
            .flat_map(|h| h.elements)
            .chain(signal0.nullifier)
            .chain(topic0)
            .collect();
        let public_inputs1: Vec<F> = self
            .0
            .cap
            .0
            .iter()
            .flat_map(|h| h.elements)
            .chain(signal1.nullifier)
            .chain(topic1)
            .collect();

        let proof_target0 = builder.add_virtual_proof_with_pis::<InnerC>(&verifier_data.common);
        pw.set_proof_with_pis_target(
            &proof_target0,
            &ProofWithPublicInputs {
                proof: signal0.proof,
                public_inputs: public_inputs0,
            },
        );
        let proof_target1 = builder.add_virtual_proof_with_pis::<InnerC>(&verifier_data.common);
        pw.set_proof_with_pis_target(
            &proof_target1,
            &ProofWithPublicInputs {
                proof: signal1.proof,
                public_inputs: public_inputs1,
            },
        );

        let vd_target = VerifierCircuitTarget {
            constants_sigmas_cap: builder
                .add_virtual_cap(verifier_data.common.config.fri_config.cap_height),
            circuit_digest: builder.add_virtual_hash(),
        };
        pw.set_cap_target(
            &vd_target.constants_sigmas_cap,
            &verifier_data.verifier_only.constants_sigmas_cap,
        );
        pw.set_hash_target(
            vd_target.circuit_digest,
            verifier_data.verifier_only.circuit_digest,
        );

        builder.verify_proof::<InnerC>(&proof_target0, &vd_target, &verifier_data.common);
        builder.verify_proof::<InnerC>(&proof_target1, &vd_target, &verifier_data.common);

        let data = builder.build();
        let recursive_proof = data.prove(pw).unwrap();

        data.verify(recursive_proof.clone()).unwrap();

        (signal0.nullifier, signal1.nullifier, recursive_proof.proof)
    }
}
