//! Most of these operations here are not suitable for general purpose matrix
//! operations. Besides vector multiplication other operations are presented
//! with the intention of construction of parameters and are not used in the
//! actual permutation process.

use plonky2::field::{goldilocks_field::GoldilocksField, types::Field};

type F = GoldilocksField;

#[derive(PartialEq, Debug, Clone)]
pub struct Matrix<const T: usize>(pub [[F; T]; T]);

impl<const T: usize> Default for Matrix<T> {
    fn default() -> Self {
        Matrix([[F::from_canonical_u64(0); T]; T])
    }
}

impl<const T: usize> Matrix<T> {
    #[inline]
    pub fn zero_matrix() -> Self {
        Self([[F::from_canonical_u64(0); T]; T])
    }

    #[inline]
    pub fn identity() -> Self {
        let mut m = Self::zero_matrix();
        for i in 0..T {
            m.set(i, i, F::from_canonical_u64(1))
        }
        m
    }

    pub fn set(&mut self, row: usize, col: usize, value: F) {
        self.0[row][col] = value;
    }

    pub fn from_vec(vec: Vec<Vec<F>>) -> Self {
        let n = vec.len();
        // Expect square and well formed matrix
        for row in vec.iter() {
            assert_eq!(row.len(), n);
        }

        let mut result = Self::default();
        for (row_result, row_inverted) in result.0.iter_mut().zip(vec.iter()) {
            for (result_cell, cell) in row_result.iter_mut().zip(row_inverted.iter()) {
                *result_cell = *cell
            }
        }
        result
    }

    pub fn transpose(&self) -> Self {
        let mut result = Self::default();
        for (i, row) in self.0.iter().enumerate() {
            for (j, e) in row.iter().enumerate() {
                result.0[j][i] = *e
            }
        }
        result
    }

    pub fn mul(&self, other: &Self) -> Self {
        let mut result = Self::default();
        for i in 0..T {
            for j in 0..T {
                for k in 0..T {
                    result.0[i][j] += self.0[i][k] * other.0[k][j];
                }
            }
        }
        result
    }

    pub fn mul_vector(&self, v: &[F; T]) -> [F; T] {
        let mut result = [F::from_canonical_u64(0); T];
        for (row, cell) in self.0.iter().zip(result.iter_mut()) {
            for (a_i, v_i) in row.iter().zip(v.iter()) {
                *cell += *v_i * *a_i;
            }
        }
        result
    }

    // This is very pesky implementation of matrix inversion,
    // It won't even alarm when a matrix is not invertable.
    pub fn invert(&self) -> Self {
        let identity = Self::identity();

        let mut m: Vec<Vec<F>> = identity
            .0
            .iter()
            .zip(self.0.iter())
            .map(|(u_row, v_row)| {
                let mut row = v_row.to_vec();
                row.extend(u_row.to_vec());
                row
            })
            .collect();

        for i in 0..T {
            for j in 0..T {
                if i != j {
                    let r = m[j][i] * m[i][i].inverse();
                    for k in 0..2 * T {
                        let e = m[i][k];
                        m[j][k] -= r * e;
                    }
                }
            }
        }

        let mut res = Self::default();
        for (i, row) in m.iter_mut().enumerate().take(T) {
            for j in T..2 * T {
                let e = row[i];
                row[j] *= e.inverse()
            }
        }

        for (i, row) in m.iter().enumerate().take(T) {
            for j in 0..T {
                res.set(i, j, row[j + T]);
            }
        }
        res
    }

    #[inline]
    pub fn w<const RATE: usize>(&self) -> [F; RATE] {
        assert_eq!(RATE + 1, T);
        self.0
            .iter()
            .skip(1)
            .map(|row| row[0])
            .collect::<Vec<F>>()
            .try_into()
            .unwrap()
    }

    #[inline]
    pub fn sub<const RATE: usize>(&self) -> Matrix<RATE> {
        assert_eq!(RATE + 1, T);
        Matrix::<RATE>::from_vec(self.0.iter().skip(1).map(|row| row[1..].to_vec()).collect())
    }
}
