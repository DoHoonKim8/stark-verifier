use std::{
    cmp::min,
    ops::{Div, Sub},
};

use halo2curves::FieldExt;
use num_bigint::BigUint;
use num_traits::{Num, ToPrimitive};
use plonky2::util::{log2_strict, reverse_index_bits_in_place};

pub type FftRootTable<F> = Vec<Vec<F>>;

pub fn fft_root_table<F: FieldExt>(n: usize) -> FftRootTable<F> {
    let lg_n = log2_strict(n);
    // bases[i] = g^2^i, for i = 0, ..., lg_n - 1
    let mut bases = Vec::with_capacity(lg_n);
    let power = BigUint::from_str_radix(&F::MODULUS[2..], 16)
        .unwrap()
        .to_u64()
        .unwrap()
        .sub(1)
        .div(1 << lg_n)
        .to_le();
    let mut base = F::multiplicative_generator().pow(&[power, 0, 0, 0]);
    bases.push(base);
    for _ in 1..lg_n {
        base = base.square(); // base = g^2^_
        bases.push(base);
    }

    let mut root_table = Vec::with_capacity(lg_n);
    for lg_m in 1..=lg_n {
        let half_m = 1 << (lg_m - 1);
        let base = bases[lg_n - lg_m];
        let mut root_row = vec![];
        for i in 0..half_m.max(2) {
            root_row.push(base.pow(&[(i as u64).to_le(), 0, 0, 0]));
        }
        root_table.push(root_row);
    }
    root_table
}

#[inline]
pub fn ifft<F: FieldExt>(poly: Vec<F>) -> Vec<F> {
    ifft_with_options(poly, None, None)
}

pub fn ifft_with_options<F: FieldExt>(
    poly: Vec<F>,
    zero_factor: Option<usize>,
    root_table: Option<&FftRootTable<F>>,
) -> Vec<F> {
    let n = poly.len();
    let lg_n = log2_strict(n);
    let n_inv = F::TWO_INV.pow(&[(lg_n as u64).to_le(), 0, 0, 0]);

    let mut buffer = poly;
    fft_dispatch(&mut buffer, zero_factor, root_table);

    // We reverse all values except the first, and divide each by n.
    buffer[0] *= n_inv;
    buffer[n / 2] *= n_inv;
    for i in 1..(n / 2) {
        let j = n - i;
        let coeffs_i = buffer[j] * n_inv;
        let coeffs_j = buffer[i] * n_inv;
        buffer[i] = coeffs_i;
        buffer[j] = coeffs_j;
    }
    buffer
}

#[inline]
fn fft_dispatch<F: FieldExt>(
    input: &mut [F],
    zero_factor: Option<usize>,
    root_table: Option<&FftRootTable<F>>,
) {
    let computed_root_table = if root_table.is_some() {
        None
    } else {
        Some(fft_root_table(input.len()))
    };
    let used_root_table = root_table.or(computed_root_table.as_ref()).unwrap();

    fft_classic(input, zero_factor.unwrap_or(0), used_root_table);
}

/// FFT implementation based on Section 32.3 of "Introduction to
/// Algorithms" by Cormen et al.
///
/// The parameter r signifies that the first 1/2^r of the entries of
/// input may be non-zero, but the last 1 - 1/2^r entries are
/// definitely zero.
pub(crate) fn fft_classic<F: FieldExt>(values: &mut [F], r: usize, root_table: &FftRootTable<F>) {
    reverse_index_bits_in_place(values);

    let n = values.len();
    let lg_n = log2_strict(n);

    if root_table.len() != lg_n {
        panic!(
            "Expected root table of length {}, but it was {}.",
            lg_n,
            root_table.len()
        );
    }

    // After reverse_index_bits, the only non-zero elements of values
    // are at indices i*2^r for i = 0..n/2^r.  The loop below copies
    // the value at i*2^r to the positions [i*2^r + 1, i*2^r + 2, ...,
    // (i+1)*2^r - 1]; i.e. it replaces the 2^r - 1 zeros following
    // element i*2^r with the value at i*2^r.  This corresponds to the
    // first r rounds of the FFT when there are 2^r zeros at the end
    // of the original input.
    if r > 0 {
        // if r == 0 then this loop is a noop.
        let mask = !((1 << r) - 1);
        for i in 0..n {
            values[i] = values[i & mask];
        }
    }

    fft_classic_simd::<F>(values, r, lg_n, root_table);
}

/// Generic FFT implementation that works with both scalar and packed inputs.
// #[unroll_for_loops]
fn fft_classic_simd<F: FieldExt>(
    values: &mut [F],
    r: usize,
    lg_n: usize,
    root_table: &FftRootTable<F>,
) {
    // let lg_packed_width = 0;
    // let packed_values = values;
    // let packed_n = packed_values.len();
    // debug_assert!(packed_n == (1 << lg_n));

    // // Want the below for loop to unroll, hence the need for a literal.
    // // This loop will not run when P is a scalar.
    // assert!(lg_packed_width <= 4);
    // for lg_half_m in 0..4 {
    //     if (r..min(lg_n, lg_packed_width)).contains(&lg_half_m) {
    //         // Intuitively, we split values into m slices: subarr[0], ..., subarr[m - 1]. Each of
    //         // those slices is split into two halves: subarr[j].left, subarr[j].right. We do
    //         // (subarr[j].left[k], subarr[j].right[k])
    //         //   := f(subarr[j].left[k], subarr[j].right[k], omega[k]),
    //         // where f(u, v, omega) = (u + omega * v, u - omega * v).
    //         let half_m = 1 << lg_half_m;

    //         // Set omega to root_table[lg_half_m][0..half_m] but repeated.
    //         let mut omega = F::default();
    //         for (j, omega_j) in omega.as_slice_mut().iter_mut().enumerate() {
    //             *omega_j = root_table[lg_half_m][j % half_m];
    //         }

    //         for k in (0..packed_n).step_by(2) {
    //             // We have two vectors and want to do math on pairs of adjacent elements (or for
    //             // lg_half_m > 0, pairs of adjacent blocks of elements). .interleave does the
    //             // appropriate shuffling and is its own inverse.
    //             let (u, v) = packed_values[k].interleave(packed_values[k + 1], half_m);
    //             let t = omega * v;
    //             (packed_values[k], packed_values[k + 1]) = (u + t).interleave(u - t, half_m);
    //         }
    //     }
    // }

    // // We've already done the first lg_packed_width (if they were required) iterations.
    // let s = max(r, lg_packed_width);

    // for lg_half_m in s..lg_n {
    //     let lg_m = lg_half_m + 1;
    //     let m = 1 << lg_m; // Subarray size (in field elements).
    //     let packed_m = m >> lg_packed_width; // Subarray size (in vectors).
    //     let half_packed_m = packed_m / 2;
    //     debug_assert!(half_packed_m != 0);

    //     // omega values for this iteration, as slice of vectors
    //     let omega_table = P::pack_slice(&root_table[lg_half_m][..]);
    //     for k in (0..packed_n).step_by(packed_m) {
    //         for j in 0..half_packed_m {
    //             let omega = omega_table[j];
    //             let t = omega * packed_values[k + half_packed_m + j];
    //             let u = packed_values[k + j];
    //             packed_values[k + j] = u + t;
    //             packed_values[k + half_packed_m + j] = u - t;
    //         }
    //     }
    // }
}
