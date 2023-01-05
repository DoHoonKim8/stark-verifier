use crate::merkle::{Digest, MerkleTreeCircuit, D, F};
use anyhow::Result;
use plonky2::{
    field::goldilocks_field::GoldilocksField,
    gates::noop::NoopGate,
    hash::{merkle_tree::MerkleTree, poseidon::PoseidonHash},
    iop::witness::{PartialWitness, WitnessWrite},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CommonCircuitData, VerifierOnlyCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};

type ProofTuple<F, C, const D: usize> = (
    ProofWithPublicInputs<F, C, D>,
    VerifierOnlyCircuitData<C, D>,
    CommonCircuitData<F, D>,
);

impl MerkleTreeCircuit {
    fn recursive_proof<C: GenericConfig<D, F = F>, InnerC: GenericConfig<D, F = F>>(
        inner: &ProofTuple<F, InnerC, D>,
        config: &CircuitConfig,
        min_degree_bits: Option<usize>,
        tree_height: usize,
        merkle_tree: &MerkleTree<GoldilocksField, PoseidonHash>,
        public_key_index: usize,
        private_key: Digest,
    ) -> Result<ProofTuple<F, C, D>>
    where
        InnerC::Hasher: AlgebraicHasher<F>,
    {
        let (inner_proof, inner_vd, inner_cd) = inner;

        let mut builder = CircuitBuilder::<F, D>::new(config.clone());
        let mut pw = PartialWitness::new();
        let pt = builder.add_virtual_proof_with_pis::<InnerC>(&inner_cd);
        pw.set_proof_with_pis_target(&pt, &inner_proof);

        let inner_data = builder.add_virtual_verifier_data(inner_cd.config.fri_config.cap_height);
        pw.set_cap_target(
            &inner_data.constants_sigmas_cap,
            &inner_vd.constants_sigmas_cap,
        );
        pw.set_hash_target(inner_data.circuit_digest, inner_vd.circuit_digest);

        builder.verify_proof::<InnerC>(&pt, &inner_data, &inner_cd);

        if let Some(min_degree_bits) = min_degree_bits {
            // We don't want to pad all the way up to 2^min_degree_bits, as the builder will add a
            // few special gates afterward. So just pad to 2^(min_degree_bits - 1) + 1. Then the
            // builder will pad to the next power of two, 2^min_degree_bits.
            let min_gates = (1 << (min_degree_bits - 1)) + 1;
            for _ in builder.num_gates()..min_gates {
                builder.add_gate(NoopGate, vec![]);
            }
        }

        let merkle_tree_circuit =
            MerkleTreeCircuit::construct(MerkleTreeCircuit::configure(&mut builder, tree_height));
        merkle_tree_circuit.assign_targets(
            &mut pw,
            merkle_tree.cap.0[0],
            merkle_tree.prove(public_key_index),
            private_key,
            public_key_index,
            merkle_tree_circuit.targets(),
        );

        let data = builder.build();
        let proof = data.prove(pw)?;

        data.verify(proof.clone())?;

        Ok((proof, data.verifier_only, data.common))
    }
}

#[cfg(test)]
mod tests {
    use crate::merkle::{Digest, MerkleTreeCircuit, D, F};
    use anyhow::Result;
    use plonky2::field::types::{Field, Sample};
    use plonky2::hash::{merkle_tree::MerkleTree, poseidon::PoseidonHash};
    use plonky2::iop::witness::PartialWitness;
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
    use plonky2::plonk::config::{Hasher, PoseidonGoldilocksConfig};

    #[test]
    fn merkle_recursion_test() -> Result<()> {
        let n = 1 << 10;
        let private_keys: Vec<Digest> = (0..n).map(|_| F::rand_array()).collect();
        let public_keys: Vec<Vec<F>> = private_keys
            .iter()
            .map(|&sk| {
                PoseidonHash::hash_no_pad(&[sk, [F::ZERO; 4]].concat())
                    .elements
                    .to_vec()
            })
            .collect();
        let merkle_tree: MerkleTree<F, PoseidonHash> = MerkleTree::new(public_keys, 0);

        let public_key_index = 12;
        let config = CircuitConfig::standard_recursion_zk_config();
        let mut builder = CircuitBuilder::new(config.clone());
        let mut pw: PartialWitness<F> = PartialWitness::new();

        let tree_height = 10;
        let targets = MerkleTreeCircuit::configure(&mut builder, tree_height);
        let circuit = MerkleTreeCircuit::construct(targets);
        circuit.assign_targets(
            &mut pw,
            merkle_tree.cap.0[0],
            merkle_tree.prove(public_key_index),
            private_keys[public_key_index],
            public_key_index,
            circuit.targets(),
        );

        let data: CircuitData<F, PoseidonGoldilocksConfig, D> = builder.build();
        let proof = data.prove(pw)?;

        data.verify(proof.clone())?;

        let inner = (proof, data.verifier_only, data.common);
        let public_key_index2 = 21;
        MerkleTreeCircuit::recursive_proof::<PoseidonGoldilocksConfig, PoseidonGoldilocksConfig>(
            &inner,
            &config,
            None,
            tree_height,
            &merkle_tree,
            public_key_index2,
            private_keys[public_key_index2],
        )?;

        Ok(())
    }
}
