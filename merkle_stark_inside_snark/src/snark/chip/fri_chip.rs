use halo2_proofs::{arithmetic::Field, plonk::Error};
use halo2curves::{goldilocks::fp::Goldilocks, group::ff::PrimeField, FieldExt};
use halo2wrong::RegionCtx;
use halo2wrong_maingate::{power_of_two, AssignedValue, Term};
use itertools::Itertools;
use poseidon::Spec;

use crate::snark::types::{
    assigned::{
        AssignedExtensionFieldValue, AssignedFriChallenges, AssignedFriInitialTreeProofValues,
        AssignedFriOpenings, AssignedFriProofValues, AssignedFriQueryRoundValues,
        AssignedMerkleCapValues,
    },
    common_data::FriParams,
    fri::{FriBatchInfo, FriInstanceInfo},
};

use super::{
    goldilocks_chip::{GoldilocksChip, GoldilocksChipConfig},
    goldilocks_extension_chip::GoldilocksExtensionChip,
    merkle_proof_chip::MerkleProofChip,
    vector_chip::VectorChip,
};

pub struct FriVerifierChip<F: FieldExt> {
    goldilocks_chip_config: GoldilocksChipConfig<F>,
    spec: Spec<Goldilocks, 12, 11>,
    /// Representative `g` of the coset used in FRI, so that LDEs in FRI are done over `gH`.
    offset: AssignedValue<F>,
    /// The degree of the purported codeword, measured in bits.
    fri_params: FriParams,
    /// merkle proofs for the initial polynomials before batching
    initial_merkle_caps: Vec<AssignedMerkleCapValues<F>>,
    fri_challenges: AssignedFriChallenges<F, 2>,
    fri_openings: AssignedFriOpenings<F, 2>,
    fri_proof: AssignedFriProofValues<F, 2>,
    fri_instance_info: FriInstanceInfo<F, 2>,
}

impl<F: FieldExt> FriVerifierChip<F> {
    pub fn construct(
        goldilocks_chip_config: &GoldilocksChipConfig<F>,
        spec: Spec<Goldilocks, 12, 11>,
        offset: &AssignedValue<F>,
        fri_params: FriParams,
        initial_merkle_caps: Vec<AssignedMerkleCapValues<F>>,
        fri_challenges: AssignedFriChallenges<F, 2>,
        fri_openings: AssignedFriOpenings<F, 2>,
        fri_proof: AssignedFriProofValues<F, 2>,
        fri_instance_info: FriInstanceInfo<F, 2>,
    ) -> Self {
        Self {
            goldilocks_chip_config: goldilocks_chip_config.clone(),
            spec,
            offset: offset.clone(),
            fri_params,
            initial_merkle_caps,
            fri_challenges,
            fri_openings,
            fri_proof,
            fri_instance_info,
        }
    }

    fn goldilocks_chip(&self) -> GoldilocksChip<F> {
        GoldilocksChip::new(&self.goldilocks_chip_config)
    }

    fn goldilocks_extension_chip(&self) -> GoldilocksExtensionChip<F> {
        GoldilocksExtensionChip::new(&self.goldilocks_chip_config)
    }

    fn verify_proof_of_work(&self) {}

    fn compute_reduced_openings(
        &self,
        ctx: &mut RegionCtx<'_, F>,
    ) -> Result<Vec<AssignedExtensionFieldValue<F, 2>>, Error> {
        let goldilocks_extension_chip = GoldilocksExtensionChip::new(&self.goldilocks_chip_config);
        self.fri_openings
            .batches
            .iter()
            .map(|batch| {
                goldilocks_extension_chip.reduce_extension(
                    ctx,
                    &self.fri_challenges.fri_alpha,
                    &batch.values,
                )
            })
            .collect()
    }

    fn calculate_cap_index(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        x_index_bits: &[AssignedValue<F>],
    ) -> Result<AssignedValue<F>, Error> {
        let goldilocks_chip = self.goldilocks_chip();
        let terms = &x_index_bits[x_index_bits.len() - self.fri_params.config.cap_height..]
            .iter()
            .enumerate()
            .map(|(i, bit)| Term::Assigned(&bit, power_of_two(i)))
            .collect_vec();
        goldilocks_chip.compose(ctx, terms, Goldilocks::zero())
    }

    // evaluation proof for initial polynomials at `x`
    fn verify_initial_merkle_proof(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        x_index_bits: &[AssignedValue<F>],
        initial_trees_proof: &AssignedFriInitialTreeProofValues<F>,
        round: usize,
    ) -> Result<(), Error> {
        let merkle_proof_chip =
            MerkleProofChip::new(&self.goldilocks_chip_config, self.spec.clone());
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
        ctx: &mut RegionCtx<'_, F>,
        // `x` is the initially selected point in FRI
        x: AssignedValue<F>,
        initial_trees_proof: &AssignedFriInitialTreeProofValues<F>,
        reduced_openings: &[AssignedExtensionFieldValue<F, 2>],
    ) -> Result<AssignedExtensionFieldValue<F, 2>, Error> {
        let goldilocks_extension_chip = self.goldilocks_extension_chip();
        let x = goldilocks_extension_chip.convert_to_extension(ctx, &x)?;
        let alpha = self.fri_challenges.fri_alpha.clone();
        let mut sum = goldilocks_extension_chip.zero_extension(ctx)?;
        for (batch, reduced_openings) in self
            .fri_instance_info
            .batches
            .iter()
            .zip(reduced_openings.iter())
        {
            let FriBatchInfo { point, polynomials } = batch;
            let evals = polynomials
                .iter()
                .map(|p| {
                    let poly_blinding = self.fri_instance_info.oracles[p.oracle_index].blinding;
                    let salted = self.fri_params.hiding && poly_blinding;
                    initial_trees_proof.unsalted_eval(p.oracle_index, p.polynomial_index, salted)
                })
                .collect_vec();
            let reduced_evals = goldilocks_extension_chip.reduce(ctx, &alpha, &evals)?;
            let numerator =
                goldilocks_extension_chip.sub_extension(ctx, &reduced_evals, reduced_openings)?;
            let denominator = goldilocks_extension_chip.sub_extension(ctx, &x, point)?;
            sum = goldilocks_extension_chip.shift(ctx, &alpha, evals.len(), &reduced_evals)?;
            sum =
                goldilocks_extension_chip.div_add_extension(ctx, &numerator, &denominator, &sum)?;
        }
        Ok(sum)
    }

    /// obtain subgroup element at index `x_index_bits` from the domain
    /// `x_index_bits` should be represented in little-endian order
    fn x_from_subgroup(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        x_index_bits: &[AssignedValue<F>],
    ) -> Result<AssignedValue<F>, Error> {
        let goldilocks_chip = self.goldilocks_chip();
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
        let mut x = goldilocks_chip.assign_constant(ctx, Goldilocks::one())?;
        for (i, bit) in x_index_bits.iter().enumerate() {
            let is_zero_bit = goldilocks_chip.is_zero(ctx, bit)?;
            let one = goldilocks_chip.assign_constant(ctx, Goldilocks::one())?;

            let power = u64::from(power_of_two::<Goldilocks>(i)).to_le();
            let base = goldilocks_chip.assign_constant(ctx, omega.pow(&[power, 0, 0, 0]))?;
            let multiplicand = goldilocks_chip.select(ctx, &one, &base, &is_zero_bit)?;
            x = goldilocks_chip.mul(ctx, &x, &multiplicand)?;
        }
        Ok(x)
    }

    fn check_consistency(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        x_index: &AssignedValue<F>,
        round_proof: &AssignedFriQueryRoundValues<F, 2>,
        reduced_openings: &[AssignedExtensionFieldValue<F, 2>],
        round: usize,
    ) -> Result<(), Error> {
        let goldilocks_chip = self.goldilocks_chip();
        let lde_bits = self.fri_params.lde_bits();

        // `x_index` is the index of point selected from initial domain
        let mut x_index_bits = goldilocks_chip
            .to_bits(ctx, x_index, F::NUM_BITS as usize)?
            .iter()
            .take(lde_bits)
            .map(|v| v.clone())
            .collect_vec();

        // verify evaluation proofs for initial polynomials at `x_index` point
        self.verify_initial_merkle_proof(
            ctx,
            &x_index_bits,
            &round_proof.initial_trees_proof,
            round,
        )?;

        let mut x_from_subgroup = self.x_from_subgroup(ctx, &x_index_bits)?;
        let x = goldilocks_chip.mul(ctx, &self.offset, &x_from_subgroup)?;

        let mut prev_eval = self.batch_initial_polynomials(
            ctx,
            x,
            &round_proof.initial_trees_proof,
            reduced_openings,
        )?;

        for (i, &arity_bits) in self.fri_params.reduction_arity_bits.iter().enumerate() {
            let evals = &round_proof.steps[i].evals;

            // Split x_index into the index of the coset x is in, and the index of x within that coset.
            // reminder : `x_index_bits` is in little-endian, and it is folded by 2^{arity_bits}
            let coset_index_bits = x_index_bits[arity_bits..].to_vec();
            let x_index_within_coset_bits = &x_index_bits[..arity_bits];
            let x_index_within_coset =
                goldilocks_chip.from_bits(ctx, &x_index_within_coset_bits.to_vec())?;

            // check the consistency of `prev_eval` and `next_eval`
            for i in 0..2 {
                let vector_chip = VectorChip::new(
                    &self.goldilocks_chip_config,
                    evals.iter().map(|eval| eval.0[i].clone()).collect_vec(),
                );
                let next_eval_i = vector_chip.access(ctx, &x_index_within_coset)?;
                goldilocks_chip.assert_equal(ctx, &prev_eval.0[i], &next_eval_i)?;
            }

            // computes `P'(x^arity)` where `arity = 1 << arity_bits` from `P(x*g^i), (i = 0, ..., arity)` where
            // g is `arity`-th primitive root of unity. P' is FRI folded polynomial.
            let arity = 1 << arity_bits;
            // challenge `beta` for folding

            // Update the point x to x^arity.
            x_from_subgroup = goldilocks_chip.exp_power_of_2(ctx, &x_from_subgroup, arity_bits)?;

            x_index_bits = coset_index_bits;
        }
        Ok(())
    }

    pub fn verify_fri_proof(&self, ctx: &mut RegionCtx<'_, F>) -> Result<(), Error> {
        // this value is the same across all queries
        let reduced_openings = self.compute_reduced_openings(ctx)?;

        for (i, round_proof) in self.fri_proof.query_round_proofs.iter().enumerate() {
            self.check_consistency(
                ctx,
                &self.fri_challenges.fri_query_indices[i],
                round_proof,
                &reduced_openings,
                i,
            )?;
        }

        Ok(())
    }
}
