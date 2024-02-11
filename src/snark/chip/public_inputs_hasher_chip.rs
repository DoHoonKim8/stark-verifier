use halo2_proofs::{halo2curves::ff::PrimeField, plonk::Error};
use halo2wrong_maingate::{AssignedValue, Term};
use plonky2::{
    field::{goldilocks_field::GoldilocksField, types::Field},
    hash::keccak::SPONGE_WIDTH,
};

use crate::snark::context::RegionCtx;

use super::{
    goldilocks_chip::{GoldilocksChip, GoldilocksChipConfig},
    native_chip::utils::goldilocks_to_fe,
    poseidon_spec::spec::{SparseMDSMatrix, Spec, State},
};

const T: usize = SPONGE_WIDTH;
const T_MINUS_ONE: usize = T - 1;
const RATE: usize = 8;

/// `AssignedState` is composed of `T` sized assigned values
#[derive(Debug, Clone)]
pub struct AssignedState<F: PrimeField, const T: usize>(pub(super) [AssignedValue<F>; T]);

/// `HasherChip` is basically responsible for contraining permutation part of
/// transcript pipeline
#[derive(Debug, Clone)]
pub struct PublicInputsHasherChip<F: PrimeField> {
    state: AssignedState<F, T>,
    absorbing: Vec<AssignedValue<F>>,
    output_buffer: Vec<AssignedValue<F>>,
    spec: Spec<T, T_MINUS_ONE>,
    goldilocks_chip_config: GoldilocksChipConfig<F>,
}

impl<F: PrimeField> PublicInputsHasherChip<F> {
    // Constructs new hasher chip with assigned initial state
    pub fn new(
        // TODO: we can remove initial state assingment in construction
        ctx: &mut RegionCtx<'_, F>,
        goldilocks_chip_config: &GoldilocksChipConfig<F>,
    ) -> Result<Self, Error> {
        let spec = Spec::<T, T_MINUS_ONE>::new(8, 22);
        let goldilocks_chip = GoldilocksChip::new(goldilocks_chip_config);

        let initial_state = State::<T>::default()
            .words()
            .iter()
            .map(|word| goldilocks_chip.assign_constant(ctx, *word))
            .collect::<Result<Vec<AssignedValue<F>>, Error>>()?;

        Ok(Self {
            state: AssignedState(initial_state.try_into().unwrap()),
            spec: spec.clone(),
            absorbing: vec![],
            output_buffer: vec![],
            goldilocks_chip_config: goldilocks_chip_config.clone(),
        })
    }

    /// Appends field elements to the absorbation line. It won't perform
    /// permutation here
    pub fn update(
        &mut self,
        _ctx: &mut RegionCtx<'_, F>,
        element: &AssignedValue<F>,
    ) -> Result<(), Error> {
        self.output_buffer.clear();
        self.absorbing.push(element.clone());
        Ok(())
    }

    fn absorb_buffered_inputs(&mut self, ctx: &mut RegionCtx<'_, F>) -> Result<(), Error> {
        if self.absorbing.is_empty() {
            return Ok(());
        }
        let buffered_inputs = self.absorbing.clone();
        for input_chunk in buffered_inputs.chunks(RATE) {
            self.duplexing(ctx, input_chunk)?;
        }
        self.absorbing.clear();
        Ok(())
    }

    pub fn squeeze(
        &mut self,
        ctx: &mut RegionCtx<'_, F>,
        num_outputs: usize,
    ) -> Result<Vec<AssignedValue<F>>, Error> {
        let mut output = vec![];
        for _i in 0..num_outputs {
            self.absorb_buffered_inputs(ctx)?;

            if self.output_buffer.is_empty() {
                self.permutation(ctx)?;
                self.output_buffer = self.state.0[0..RATE].to_vec();
            }
            output.push(self.output_buffer.pop().unwrap())
        }
        Ok(output)
    }
}

impl<F: PrimeField> PublicInputsHasherChip<F> {
    /// Construct main gate
    pub fn goldilocks_chip(&self) -> GoldilocksChip<F> {
        GoldilocksChip::new(&self.goldilocks_chip_config)
    }

    /*
        Internally expose poseidion parameters and matrices
    */

    pub(super) fn r_f_half(&self) -> usize {
        self.spec.r_f() / 2
    }

    pub(super) fn constants_start(&self) -> Vec<[GoldilocksField; T]> {
        self.spec.constants().start().clone()
    }

    pub(super) fn constants_partial(&self) -> Vec<GoldilocksField> {
        self.spec.constants().partial().clone()
    }

    pub(super) fn constants_end(&self) -> Vec<[GoldilocksField; T]> {
        self.spec.constants().end().clone()
    }

    pub(super) fn mds(&self) -> [[GoldilocksField; T]; T] {
        self.spec.mds_matrices().mds().rows()
    }

    pub(super) fn pre_sparse_mds(&self) -> [[GoldilocksField; T]; T] {
        self.spec.mds_matrices().pre_sparse_mds().rows()
    }

    pub(super) fn sparse_matrices(&self) -> Vec<SparseMDSMatrix<T, T_MINUS_ONE>> {
        self.spec.mds_matrices().sparse_matrices().clone()
    }
}

impl<F: PrimeField> PublicInputsHasherChip<F> {
    /// Applies full state sbox then adds constants to each word in the state
    fn sbox_full(
        &mut self,
        ctx: &mut RegionCtx<'_, F>,
        constants: &[GoldilocksField; T],
    ) -> Result<(), Error> {
        let goldilocks_chip = self.goldilocks_chip();
        for (word, constant) in self.state.0.iter_mut().zip(constants.iter()) {
            let word2 = goldilocks_chip.mul(ctx, word, word)?;
            let word4 = goldilocks_chip.mul(ctx, &word2, &word2)?;
            let word6 = goldilocks_chip.mul(ctx, &word2, &word4)?;
            *word = goldilocks_chip.mul_add_constant(ctx, &word6, word, *constant)?;
        }
        Ok(())
    }

    /// Applies sbox to the first word then adds constants to each word in the
    /// state
    fn sbox_part(
        &mut self,
        ctx: &mut RegionCtx<'_, F>,
        constant: GoldilocksField,
    ) -> Result<(), Error> {
        let goldilocks_chip = self.goldilocks_chip();
        let word = &mut self.state.0[0];
        let word2 = goldilocks_chip.mul(ctx, word, word)?;
        let word4 = goldilocks_chip.mul(ctx, &word2, &word2)?;
        let word6 = goldilocks_chip.mul(ctx, &word2, &word4)?;
        *word = goldilocks_chip.mul_add_constant(ctx, &word6, word, constant)?;

        Ok(())
    }

    // Adds pre constants to the state.
    fn absorb_with_pre_constants(
        &mut self,
        ctx: &mut RegionCtx<'_, F>,
        pre_constants: &[GoldilocksField; T],
    ) -> Result<(), Error> {
        let goldilocks_chip = self.goldilocks_chip();

        // Add pre constants
        for (word, constant) in self.state.0.iter_mut().zip(pre_constants.iter()) {
            *word = goldilocks_chip.add_constant(ctx, word, *constant)?;
        }

        Ok(())
    }

    /// Applies MDS State multiplication
    fn apply_mds(
        &mut self,
        ctx: &mut RegionCtx<'_, F>,
        mds: &[[GoldilocksField; T]; T],
    ) -> Result<(), Error> {
        let goldilocks_chip = self.goldilocks_chip();
        // Calculate new state
        let new_state = mds
            .iter()
            .map(|row| {
                // term_i = s_0 * e_i_0 + s_1 * e_i_1 + ....
                let terms = self
                    .state
                    .0
                    .iter()
                    .zip(row.iter())
                    .map(|(e, word)| Term::Assigned(e, goldilocks_to_fe(*word)))
                    .collect::<Vec<Term<F>>>();

                goldilocks_chip.compose(ctx, &terms[..], GoldilocksField::ZERO)
            })
            .collect::<Result<Vec<AssignedValue<F>>, Error>>()?;

        // Assign new state
        for (word, new_word) in self.state.0.iter_mut().zip(new_state.into_iter()) {
            *word = new_word
        }

        Ok(())
    }

    /// Applies sparse MDS to the state
    fn apply_sparse_mds(
        &mut self,
        ctx: &mut RegionCtx<'_, F>,
        mds: &SparseMDSMatrix<T, T_MINUS_ONE>,
    ) -> Result<(), Error> {
        let goldilocks_chip = self.goldilocks_chip();
        // For the 0th word
        let terms = self
            .state
            .0
            .iter()
            .zip(mds.row().iter())
            .map(|(e, word)| Term::Assigned(e, goldilocks_to_fe(*word)))
            .collect::<Vec<Term<F>>>();
        let mut new_state =
            vec![self
                .goldilocks_chip()
                .compose(ctx, &terms[..], GoldilocksField::ZERO)?];

        // Rest of the trainsition ie the sparse part
        for (e, word) in mds.col_hat().iter().zip(self.state.0.iter().skip(1)) {
            new_state.push(goldilocks_chip.compose(
                ctx,
                &[
                    Term::Assigned(&self.state.0[0], goldilocks_to_fe(*e)),
                    Term::Assigned(word, F::from(1)),
                ],
                GoldilocksField::ZERO,
            )?);
        }

        // Assign new state
        for (word, new_word) in self.state.0.iter_mut().zip(new_state.into_iter()) {
            *word = new_word
        }

        Ok(())
    }

    /// Constrains poseidon permutation while mutating the given state
    pub fn permutation(&mut self, ctx: &mut RegionCtx<'_, F>) -> Result<(), Error> {
        let r_f = self.r_f_half();
        let mds = self.mds();
        let pre_sparse_mds = self.pre_sparse_mds();
        let sparse_matrices = self.sparse_matrices();

        // First half of the full rounds
        let constants = self.constants_start();
        self.absorb_with_pre_constants(ctx, &constants[0])?;
        for constants in constants.iter().skip(1).take(r_f - 1) {
            self.sbox_full(ctx, constants)?;
            self.apply_mds(ctx, &mds)?;
        }
        self.sbox_full(ctx, constants.last().unwrap())?;
        self.apply_mds(ctx, &pre_sparse_mds)?;

        // Partial rounds
        let constants = self.constants_partial();
        for (constant, sparse_mds) in constants.iter().zip(sparse_matrices.iter()) {
            self.sbox_part(ctx, *constant)?;
            self.apply_sparse_mds(ctx, sparse_mds)?;
        }

        // Second half of the full rounds
        let constants = self.constants_end();
        for constants in constants.iter() {
            self.sbox_full(ctx, constants)?;
            self.apply_mds(ctx, &mds)?;
        }
        self.sbox_full(ctx, &[GoldilocksField::ZERO; T])?;
        self.apply_mds(ctx, &mds)?;

        Ok(())
    }

    fn duplexing(
        &mut self,
        ctx: &mut RegionCtx<'_, F>,
        input: &[AssignedValue<F>],
    ) -> Result<(), Error> {
        for (word, input) in self.state.0.iter_mut().zip(input.iter()) {
            *word = input.clone();
        }
        self.permutation(ctx)?;

        self.output_buffer.clear();
        self.output_buffer.extend_from_slice(&self.state.0[0..RATE]);
        Ok(())
    }

    pub fn hash(
        &mut self,
        ctx: &mut RegionCtx<'_, F>,
        inputs: Vec<AssignedValue<F>>,
        num_outputs: usize,
    ) -> Result<Vec<AssignedValue<F>>, Error> {
        // Flush the input que
        self.absorbing.clear();

        for chunk in inputs.chunks(RATE) {
            for (word, input) in self.state.0.iter_mut().zip(chunk.iter()) {
                *word = input.clone();
            }
            self.permutation(ctx)?;
        }

        let mut outputs = vec![];
        loop {
            for item in self.state.0.iter().take(RATE) {
                outputs.push(item.clone());
                if outputs.len() == num_outputs {
                    return Ok(outputs);
                }
            }
            self.permutation(ctx)?;
        }
    }

    pub fn permute(
        &mut self,
        ctx: &mut RegionCtx<'_, F>,
        input: Vec<AssignedValue<F>>,
        num_output: usize,
    ) -> Result<Vec<AssignedValue<F>>, Error> {
        for (word, input) in self.state.0.iter_mut().zip(input.iter()) {
            *word = input.clone();
        }
        self.permutation(ctx)?;

        let mut outputs = vec![];
        loop {
            for item in self.state.0.iter().take(RATE) {
                outputs.push(item.clone());
                if outputs.len() == num_output {
                    return Ok(outputs);
                }
            }
            self.permutation(ctx)?;
        }
    }
}
