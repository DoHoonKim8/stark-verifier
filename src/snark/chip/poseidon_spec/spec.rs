use plonky2::field::{goldilocks_field::GoldilocksField, types::Field};

use super::{constants, matrix::Matrix};
use std::ops::Index;

type F = GoldilocksField;

/// `State` is structure `T` sized field elements that are subjected to
/// permutation
#[derive(Clone, Debug, PartialEq)]
pub struct State<const T: usize>(pub [F; T]);

impl<const T: usize> Default for State<T> {
    fn default() -> Self {
        let state = [F::from_canonical_u64(0); T];
        State(state)
    }
}

impl<const T: usize> State<T> {
    /// Applies sbox for all elements of the state.
    /// Only supports `alpha = 7` sbox case.
    pub fn sbox_full(&mut self) {
        for e in self.0.iter_mut() {
            *e = e.exp_u64(7);
        }
    }

    /// Partial round sbox applies sbox to the first element of the state.
    /// Only supports `alpha = 7` sbox case
    pub fn sbox_part(&mut self) {
        self.0[0] = self.0[0].exp_u64(7);
    }

    /// Adds constants to all elements of the state
    pub fn add_constants(&mut self, constants: &[F; T]) {
        for (e, constant) in self.0.iter_mut().zip(constants.iter()) {
            *e += *constant;
        }
    }

    /// Only adds a constant to the first element of the state.It is used with
    /// optimized rounds constants where only single element is added in
    /// each partial round
    pub fn add_constant(&mut self, constant: &F) {
        self.0[0] += *constant;
    }

    /// Copies elements of the state
    pub fn words(&self) -> [F; T] {
        self.0
    }

    /// Second element of the state is the result
    pub fn result(&self) -> F {
        self.0[1]
    }
}

/// `Spec` holds construction parameters as well as constants that are used in
/// permutation step. Constants are planned to be hardcoded once transcript
/// design matures. Number of partial rounds can be deriven from number of
/// constants.
#[derive(Debug, Clone)]
pub struct Spec<const T: usize, const T_MINUS_ONE: usize> {
    pub r_f: usize,
    pub mds_matrices: MDSMatrices<T, T_MINUS_ONE>,
    pub constants: OptimizedConstants<T>,
}

impl<const T: usize, const T_MINUS_ONE: usize> Spec<T, T_MINUS_ONE> {
    /// Number of full rounds
    pub fn r_f(&self) -> usize {
        self.r_f.clone()
    }
    /// Set of MDS Matrices used in permutation line
    pub fn mds_matrices(&self) -> &MDSMatrices<T, T_MINUS_ONE> {
        &self.mds_matrices
    }
    /// Optimised round constants
    pub fn constants(&self) -> &OptimizedConstants<T> {
        &self.constants
    }
}

/// `OptimizedConstants` has round constants that are added each round. While
/// full rounds has T sized constants there is a single constant for each
/// partial round
#[derive(Debug, Clone)]
pub struct OptimizedConstants<const T: usize> {
    pub start: Vec<[F; T]>,
    pub partial: Vec<F>,
    pub end: Vec<[F; T]>,
}

impl<const T: usize> OptimizedConstants<T> {
    /// Returns rounds constants for first part of full rounds
    pub fn start(&self) -> &Vec<[F; T]> {
        &self.start
    }

    /// Returns rounds constants for partial rounds
    pub fn partial(&self) -> &Vec<F> {
        &self.partial
    }

    /// Returns rounds constants for second part of full rounds
    pub fn end(&self) -> &Vec<[F; T]> {
        &self.end
    }
}

/// `MDSMatrices` holds the MDS matrix as well as transition matrix which is
/// also called `pre_sparse_mds` and sparse matrices that enables us to reduce
/// number of multiplications in apply MDS step
#[derive(Debug, Clone)]
pub struct MDSMatrices<const T: usize, const T_MINUS_ONE: usize> {
    pub mds: MDSMatrix<T, T_MINUS_ONE>,
    pub pre_sparse_mds: MDSMatrix<T, T_MINUS_ONE>,
    pub sparse_matrices: Vec<SparseMDSMatrix<T, T_MINUS_ONE>>,
}

impl<const T: usize, const T_MINUS_ONE: usize> MDSMatrices<T, T_MINUS_ONE> {
    /// Returns original MDS matrix
    pub fn mds(&self) -> &MDSMatrix<T, T_MINUS_ONE> {
        &self.mds
    }

    /// Returns transition matrix for sparse trick
    pub fn pre_sparse_mds(&self) -> &MDSMatrix<T, T_MINUS_ONE> {
        &self.pre_sparse_mds
    }

    /// Returns sparse matrices for partial rounds
    pub fn sparse_matrices(&self) -> &Vec<SparseMDSMatrix<T, T_MINUS_ONE>> {
        &self.sparse_matrices
    }
}

/// `MDSMatrix` is applied to `State` to achive linear layer of Poseidon
#[derive(Clone, Debug)]
pub struct MDSMatrix<const T: usize, const T_MINUS_ONE: usize>(pub Matrix<T>);

impl<const T: usize, const T_MINUS_ONE: usize> Index<usize> for MDSMatrix<T, T_MINUS_ONE> {
    type Output = [F; T];

    fn index(&self, idx: usize) -> &Self::Output {
        &self.0 .0[idx]
    }
}

impl<const T: usize, const T_MINUS_ONE: usize> MDSMatrix<T, T_MINUS_ONE> {
    // /// Applies `MDSMatrix` to the state
    // pub fn apply(&self, state: &mut State<T>) {
    //     state.0 = self.0.mul_vector(&state.0);
    // }

    // /// Given two `T` sized vector constructs the `t * t` Cauchy matrix
    // pub(super) fn cauchy(xs: &[F; T], ys: &[F; T]) -> Self {
    //     let mut m = Matrix::default();
    //     for (i, x) in xs.iter().enumerate() {
    //         for (j, y) in ys.iter().enumerate() {
    //             let sum = *x + *y;
    //             debug_assert!(!sum.is_zero());
    //             m.set(i, j, sum.inverse());
    //         }
    //     }
    //     MDSMatrix(m)
    // }

    /// Inverts the MDS matrix
    fn invert(&self) -> Self {
        Self(self.0.invert())
    }

    /// Used in calculation of optimized round constants. Calculates `v' = M *
    /// v` where vectors are `T` sized
    fn mul_constants(&self, v: &[F; T]) -> [F; T] {
        self.0.mul_vector(v)
    }

    /// Multiplies two MDS matrices. Used in sparse matrix calculations
    fn mul(&self, other: &Self) -> Self {
        Self(self.0.mul(&other.0))
    }

    fn transpose(&self) -> Self {
        Self(self.0.transpose())
    }

    /// See Section B in Supplementary Material https://eprint.iacr.org/2019/458.pdf
    /// Factorises an MDS matrix `M` into `M'` and `M''` where `M = M' *  M''`.
    /// Resulted `M''` matrices are the sparse ones while `M'` will contribute
    /// to the accumulator of the process
    fn factorise(&self) -> (Self, SparseMDSMatrix<T, T_MINUS_ONE>) {
        // Given `(t-1 * t-1)` MDS matrix called `hat` constructs the matrix in
        // form `[[1 | 0], [0 | m]]`
        let prime = |hat: Matrix<T_MINUS_ONE>| -> MDSMatrix<T, T_MINUS_ONE> {
            let mut prime = Matrix::identity();
            for (prime_row, hat_row) in prime.0.iter_mut().skip(1).zip(hat.0.iter()) {
                for (el_prime, el_hat) in prime_row.iter_mut().skip(1).zip(hat_row.iter()) {
                    *el_prime = *el_hat;
                }
            }
            Self(prime)
        };

        // Given `(t-1)` sized `w_hat` vector constructs the matrix in form
        // `[[m_0_0 | m_0_i], [w_hat | identity]]`
        let prime_prime = |w_hat: [F; T_MINUS_ONE]| -> Self {
            let mut prime_prime = Matrix::identity();
            prime_prime.0[0] = self.0 .0[0];
            for (row, w) in prime_prime.0.iter_mut().skip(1).zip(w_hat.iter()) {
                row[0] = *w
            }
            Self(prime_prime)
        };

        let w = self.0.w();
        let m_hat = self.0.sub::<T_MINUS_ONE>();
        let m_hat_inverse = m_hat.invert();
        let w_hat = m_hat_inverse.mul_vector(&w);
        (prime(m_hat), prime_prime(w_hat).transpose().into())
    }

    /// Returns rows of the MDS matrix
    pub fn rows(&self) -> [[F; T]; T] {
        self.0 .0
    }
}

/// `SparseMDSMatrix` are in `[row], [hat | identity]` form and used in linear
/// layer of partial rounds instead of the original MDS
#[derive(Debug, Clone)]
pub struct SparseMDSMatrix<const T: usize, const T_MINUS_ONE: usize> {
    pub row: [F; T],
    pub col_hat: [F; T_MINUS_ONE],
}

impl<const T: usize, const T_MINUS_ONE: usize> SparseMDSMatrix<T, T_MINUS_ONE> {
    /// Returns the first row
    pub fn row(&self) -> &[F; T] {
        &self.row
    }

    /// Returns the first column without first element in the first row
    pub fn col_hat(&self) -> &[F; T_MINUS_ONE] {
        &self.col_hat
    }

    /// Applies the sparse MDS matrix to the state
    pub fn apply(&self, state: &mut State<T>) {
        let words = state.words();
        state.0[0] = self
            .row
            .iter()
            .zip(words.iter())
            .fold(F::from_canonical_u64(0), |acc, (e, cell)| {
                acc + (*e * *cell)
            });

        for ((new_word, col_el), word) in (state.0)
            .iter_mut()
            .skip(1)
            .zip(self.col_hat.iter())
            .zip(words.iter().skip(1))
        {
            *new_word = *col_el * words[0] + *word;
        }
    }
}

impl<const T: usize, const T_MINUS_ONE: usize> From<MDSMatrix<T, T_MINUS_ONE>>
    for SparseMDSMatrix<T, T_MINUS_ONE>
{
    /// Assert the form and represent an MDS matrix as a sparse MDS matrix
    fn from(mds: MDSMatrix<T, T_MINUS_ONE>) -> Self {
        let mds = mds.0;
        for (i, row) in mds.0.iter().enumerate().skip(1) {
            for (j, _) in row.iter().enumerate().skip(1) {
                assert_eq!(
                    row[j],
                    if i != j {
                        F::from_canonical_u64(0)
                    } else {
                        F::from_canonical_u64(1)
                    }
                );
            }
        }

        let (mut row, mut col_hat) = (
            [F::from_canonical_u64(0); T],
            [F::from_canonical_u64(0); T_MINUS_ONE],
        );
        for (row_el, el) in row.iter_mut().zip(mds.0[0].iter()) {
            *row_el = *el
        }
        for (col_el, row) in col_hat.iter_mut().zip(mds.0.iter().skip(1)) {
            *col_el = row[0]
        }

        SparseMDSMatrix { row, col_hat }
    }
}

impl<const T: usize, const T_MINUS_ONE: usize> Spec<T, T_MINUS_ONE> {
    /// Given number of round parameters constructs new Posedion instance
    /// calculating unoptimized round constants with reference `Grain` then
    /// calculates optimized constants and sparse matrices
    pub fn new(r_f: usize, r_p: usize) -> Self {
        let mds = constants::mds_matrix::<T, T_MINUS_ONE>();
        let upoptimized_constants: Vec<[F; T]> = constants::get_round_constants();
        let constants = Self::calculate_optimized_constants(r_f, r_p, upoptimized_constants, &mds);
        let (sparse_matrices, pre_sparse_mds) = Self::calculate_sparse_matrices(r_p, &mds);

        Self {
            r_f,
            constants,
            mds_matrices: MDSMatrices {
                mds,
                sparse_matrices,
                pre_sparse_mds,
            },
        }
    }

    fn calculate_optimized_constants(
        r_f: usize,
        r_p: usize,
        constants: Vec<[F; T]>,
        mds: &MDSMatrix<T, T_MINUS_ONE>,
    ) -> OptimizedConstants<T> {
        let inverse_mds = mds.invert();
        let (number_of_rounds, r_f_half) = (r_f + r_p, r_f / 2);
        assert_eq!(constants.len(), number_of_rounds);

        // Calculate optimized constants for first half of the full rounds
        let mut constants_start: Vec<[F; T]> = vec![[F::from_canonical_u64(0); T]; r_f_half];
        constants_start[0] = constants[0].clone();
        for (optimized, constants) in constants_start
            .iter_mut()
            .skip(1)
            .zip(constants.iter().skip(1))
        {
            *optimized = inverse_mds.mul_constants(constants);
        }

        // Calculate constants for partial rounds
        let mut acc = constants[r_f_half + r_p].clone();
        let mut constants_partial = vec![F::from_canonical_u64(0); r_p];
        for (optimized, constants) in constants_partial
            .iter_mut()
            .rev()
            .zip(constants.iter().skip(r_f_half).rev().skip(r_f_half))
        {
            let mut tmp = inverse_mds.mul_constants(&acc);
            *optimized = tmp[0];

            tmp[0] = F::from_canonical_u64(0);
            for ((acc, tmp), constant) in acc
                .iter_mut()
                .zip(tmp.into_iter())
                .zip(constants.into_iter())
            {
                *acc = tmp + *constant
            }
        }
        constants_start.push(inverse_mds.mul_constants(&acc));

        // Calculate optimized constants for ending half of the full rounds
        let mut constants_end: Vec<[F; T]> = vec![[F::from_canonical_u64(0); T]; r_f_half - 1];
        for (optimized, constants) in constants_end
            .iter_mut()
            .zip(constants.iter().skip(r_f_half + r_p + 1))
        {
            *optimized = inverse_mds.mul_constants(constants);
        }

        OptimizedConstants {
            start: constants_start,
            partial: constants_partial,
            end: constants_end,
        }
    }

    fn calculate_sparse_matrices(
        r_p: usize,
        mds: &MDSMatrix<T, T_MINUS_ONE>,
    ) -> (
        Vec<SparseMDSMatrix<T, T_MINUS_ONE>>,
        MDSMatrix<T, T_MINUS_ONE>,
    ) {
        let mds = mds.transpose();
        let mut acc = mds.clone();
        let mut sparse_matrices = (0..r_p)
            .map(|_| {
                let (m_prime, m_prime_prime) = acc.factorise();
                acc = mds.mul(&m_prime);
                m_prime_prime
            })
            .collect::<Vec<SparseMDSMatrix<T, T_MINUS_ONE>>>();

        sparse_matrices.reverse();
        (sparse_matrices, acc.transpose())
    }
}
