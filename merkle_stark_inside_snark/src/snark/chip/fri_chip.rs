use halo2_proofs::{arithmetic::Field, plonk::Error};
use halo2curves::{goldilocks::fp::Goldilocks, group::ff::PrimeField, FieldExt};
use halo2wrong::RegionCtx;
use halo2wrong_maingate::{
    power_of_two, AssignedValue, MainGate, MainGateConfig, MainGateInstructions, Term,
};
use itertools::Itertools;
use poseidon::Spec;

use crate::snark::types::{
    assigned::{
        AssignedExtensionFieldValue, AssignedFriChallenges, AssignedFriInitialTreeProofValues,
        AssignedFriOpenings, AssignedFriProofValues, AssignedFriQueryRoundValues,
        AssignedMerkleCapValues,
    },
    common_data::FriParams,
};

use super::{
    goldilocks_extension_chip::GoldilocksExtensionChip, merkle_proof_chip::MerkleProofChip,
};

pub struct FriVerifierChip {
    main_gate_config: MainGateConfig,
    spec: Spec<Goldilocks, 12, 11>,
    /// Representative `g` of the coset used in FRI, so that LDEs in FRI are done over `gH`.
    offset: AssignedValue<Goldilocks>,
    /// The degree of the purported codeword, measured in bits.
    fri_params: FriParams,
    query_indices: Vec<AssignedValue<Goldilocks>>,
    /// merkle proofs for the initial polynomials before batching
    initial_merkle_caps: Vec<AssignedMerkleCapValues<Goldilocks>>,
    fri_challenges: AssignedFriChallenges<Goldilocks, 2>,
    fri_openings: AssignedFriOpenings<Goldilocks, 2>,
    fri_proof: AssignedFriProofValues<Goldilocks, 2>,
}

impl FriVerifierChip {
    pub fn construct(
        main_gate_config: &MainGateConfig,
        spec: Spec<Goldilocks, 12, 11>,
        offset: &AssignedValue<Goldilocks>,
        fri_params: FriParams,
        query_indices: Vec<AssignedValue<Goldilocks>>,
        initial_merkle_caps: Vec<AssignedMerkleCapValues<Goldilocks>>,
        fri_challenges: AssignedFriChallenges<Goldilocks, 2>,
        fri_openings: AssignedFriOpenings<Goldilocks, 2>,
        fri_proof: AssignedFriProofValues<Goldilocks, 2>,
    ) -> Self {
        Self {
            main_gate_config: main_gate_config.clone(),
            spec,
            offset: offset.clone(),
            fri_params,
            query_indices: query_indices.clone(),
            initial_merkle_caps,
            fri_challenges,
            fri_openings,
            fri_proof,
        }
    }

    fn main_gate(&self) -> MainGate<Goldilocks> {
        MainGate::<Goldilocks>::new(self.main_gate_config.clone())
    }

    fn verify_proof_of_work(&self) {}

    fn compute_reduced_openings(
        &self,
        ctx: &mut RegionCtx<'_, Goldilocks>,
    ) -> Result<Vec<AssignedExtensionFieldValue<Goldilocks, 2>>, Error> {
        let goldilocks_extension_chip = GoldilocksExtensionChip::new(&self.main_gate_config);
        self.fri_openings
            .batches
            .iter()
            .map(|batch| {
                goldilocks_extension_chip.reduce_arithmetic(
                    ctx,
                    &self.fri_challenges.fri_alpha,
                    &batch.values,
                )
            })
            .collect()
    }

    fn calculate_cap_index(
        &self,
        ctx: &mut RegionCtx<'_, Goldilocks>,
        x_index_bits: &[AssignedValue<Goldilocks>],
    ) -> Result<AssignedValue<Goldilocks>, Error> {
        let main_gate = self.main_gate();
        let terms = &x_index_bits[x_index_bits.len() - self.fri_params.config.cap_height..]
            .iter()
            .enumerate()
            .map(|(i, bit)| Term::Assigned(&bit, power_of_two(i)))
            .collect_vec();
        main_gate.compose(ctx, terms.as_slice(), Goldilocks::zero())
    }

    fn verify_initial_merkle_proof(
        &self,
        ctx: &mut RegionCtx<'_, Goldilocks>,
        x_index_bits: &[AssignedValue<Goldilocks>],
        initial_trees_proof: &AssignedFriInitialTreeProofValues<Goldilocks>,
    ) -> Result<(), Error> {
        let merkle_proof_chip = MerkleProofChip::new(&self.main_gate_config, self.spec.clone());
        let cap_index = self.calculate_cap_index(ctx, x_index_bits)?;
        for (i, ((evals, merkle_proof), cap)) in initial_trees_proof
            .evals_proofs
            .iter()
            .zip(self.initial_merkle_caps.clone())
            .enumerate()
        {
            merkle_proof_chip.verify_merkle_proof_to_cap_with_cap_index(
                ctx,
                evals,
                x_index_bits,
                &cap_index,
                &cap,
                merkle_proof,
            )?;
        }
        Ok(())
    }

    fn batch_initial_polynomials(
        &self,
        ctx: &mut RegionCtx<'_, Goldilocks>,
        // `x` is the initially selected point in FRI
        x: AssignedValue<Goldilocks>,
        reduced_openings: &[AssignedExtensionFieldValue<Goldilocks, 2>],
    ) -> Result<AssignedExtensionFieldValue<Goldilocks, 2>, Error> {
        todo!()
    }

    /// obtain subgroup element at index `x_index_bits` from the domain
    /// `x_index_bits` should be represented in little-endian order
    fn x_from_subgroup(
        &self,
        ctx: &mut RegionCtx<'_, Goldilocks>,
        x_index_bits: &[AssignedValue<Goldilocks>],
    ) -> Result<AssignedValue<Goldilocks>, Error> {
        let main_gate = self.main_gate();
        let lde_bits = self.fri_params.lde_bits();

        let g = Goldilocks::multiplicative_generator();
        // `omega` is the root of unity for initial domain in FRI
        // TODO : add function for primitive root of unity in halo2curves
        let omega = g.pow(&[
            ((halo2curves::goldilocks::fp::MODULUS - 1) / (1 << lde_bits - 1)).to_le(),
            0,
            0,
            0,
        ]);
        let mut x = main_gate.assign_constant(ctx, Goldilocks::one())?;
        for (i, bit) in x_index_bits.iter().enumerate() {
            let is_zero_bit = main_gate.is_zero(ctx, bit)?;
            let one = main_gate.assign_constant(ctx, Goldilocks::one())?;

            let power = u64::from(power_of_two::<Goldilocks>(i)).to_le();
            let base = main_gate.assign_constant(ctx, omega.pow(&[0, 0, 0, power]))?;
            let multiplicand = main_gate.select(ctx, &one, &base, &is_zero_bit)?;
            x = main_gate.mul(ctx, &x, &multiplicand)?;
        }
        Ok(x)
    }

    fn check_consistency(
        &self,
        ctx: &mut RegionCtx<'_, Goldilocks>,
        x_index: &AssignedValue<Goldilocks>,
        round_proof: &AssignedFriQueryRoundValues<Goldilocks, 2>,
        reduced_openings: &[AssignedExtensionFieldValue<Goldilocks, 2>],
    ) -> Result<(), Error> {
        let main_gate = self.main_gate();
        let lde_bits = self.fri_params.lde_bits();

        // `x_index` is the point selected from initial domain
        let x_index_bits = main_gate
            .to_bits(ctx, x_index, Goldilocks::NUM_BITS as usize)?
            .iter()
            .rev()
            .take(lde_bits)
            .map(|v| v.clone())
            .collect_vec();
        self.verify_initial_merkle_proof(ctx, &x_index_bits, &round_proof.initial_trees_proof)?;

        let x_from_subgroup = self.x_from_subgroup(ctx, &x_index_bits)?;
        let x = main_gate.mul(ctx, &self.offset, &x_from_subgroup)?;

        let mut prev_eval = self.batch_initial_polynomials(ctx, x, reduced_openings)?;

        for (i, arity_bit) in self.fri_params.reduction_arity_bits.iter().enumerate() {}
        Ok(())
    }

    pub fn verify_fri_proof(&self, ctx: &mut RegionCtx<'_, Goldilocks>) -> Result<(), Error> {
        // this value is the same across all queries
        let reduced_openings = self.compute_reduced_openings(ctx)?;

        for (i, round_proof) in self.fri_proof.query_round_proofs.iter().enumerate() {
            self.check_consistency(ctx, &self.query_indices[i], round_proof, &reduced_openings)?;
        }

        Ok(())
    }
}
