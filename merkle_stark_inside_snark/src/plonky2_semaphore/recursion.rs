use plonky2::fri::reduction_strategies::FriReductionStrategy;
use plonky2::fri::FriConfig;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, VerifierCircuitData, VerifierCircuitTarget};
use plonky2::plonk::config::PoseidonGoldilocksConfig;
use plonky2::plonk::proof::ProofWithPublicInputs;

use super::access_set::AccessSet;
use super::signal::{Digest, Signal, C, F};

type InnerC = PoseidonGoldilocksConfig;

impl AccessSet {
    pub fn aggregate_signals(
        &self,
        topic0: Digest,
        signal0: Signal,
        topic1: Digest,
        signal1: Signal,
        verifier_data: &VerifierCircuitData<F, C, 2>,
    ) -> (
        Digest,
        Digest,
        ProofWithPublicInputs<F, PoseidonGoldilocksConfig, 2>,
        VerifierCircuitData<F, C, 2>,
    ) {
        let config = CircuitConfig {
            zero_knowledge: true,
            num_wires: 135,
            num_routed_wires: 80,
            num_constants: 2,
            use_base_arithmetic_gate: true,
            security_bits: 100,
            num_challenges: 2,
            max_quotient_degree_factor: 8,
            fri_config: FriConfig {
                rate_bits: 3,
                cap_height: 4,
                proof_of_work_bits: 16,
                reduction_strategy: FriReductionStrategy::ConstantArityBits(1, 5), // 3, 5
                num_query_rounds: 28,                                              // 28
            },
        };
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

        (
            signal0.nullifier,
            signal1.nullifier,
            recursive_proof,
            data.verifier_data(),
        )
    }
}

mod tests {
    use anyhow::Result;
    use plonky2::{
        field::types::{Field, Sample},
        hash::{merkle_tree::MerkleTree, poseidon::PoseidonHash},
        plonk::config::Hasher,
    };

    use crate::{
        plonky2_semaphore::{
            access_set::AccessSet,
            signal::{Digest, F},
        },
        snark::verifier_api::{verify_inside_snark, verify_inside_snark_mock},
    };

    #[test]
    fn test_semaphore_aggregation() -> Result<()> {
        let n = 1 << 20;
        let private_keys: Vec<Digest> = (0..n).map(|_| F::rand_array()).collect();
        let public_keys: Vec<Vec<F>> = private_keys
            .iter()
            .map(|&sk| {
                PoseidonHash::hash_no_pad(&[sk, [F::ZERO; 4]].concat())
                    .elements
                    .to_vec()
            })
            .collect();
        let access_set = AccessSet(MerkleTree::new(public_keys, 0));

        let i = 12;
        let topic0 = F::rand_array();
        let (signal0, _) = access_set.make_signal(private_keys[i], topic0, i)?;

        let i = 24;
        let topic1 = F::rand_array();
        let (signal1, vd) = access_set.make_signal(private_keys[i], topic1, i)?;

        let (_, _, proof, aggregation_circuit_vd) =
            access_set.aggregate_signals(topic0, signal0, topic1, signal1, &vd);
        verify_inside_snark_mock((
            proof,
            aggregation_circuit_vd.verifier_only.clone(),
            aggregation_circuit_vd.common.clone(),
        ));
        Ok(())
    }
}
