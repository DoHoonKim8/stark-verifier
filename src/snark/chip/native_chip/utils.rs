use halo2_proofs::halo2curves::ff::PrimeField;
use halo2wrong_maingate::fe_to_big;
use num_bigint::BigUint;
use num_integer::Integer;
use plonky2::field::{
    goldilocks_field::GoldilocksField,
    types::{Field, PrimeField64 as _},
};

use crate::snark::chip::native_chip::arithmetic_chip::GOLDILOCKS_MODULUS;

pub fn fe_to_goldilocks<F: PrimeField>(x: F) -> GoldilocksField {
    let mut x_limbs = fe_to_big(x).to_u64_digits();
    assert!(x_limbs.len() <= 1);
    x_limbs.resize(1, 0);
    let x = x_limbs[0];
    assert!(x < GOLDILOCKS_MODULUS);
    GoldilocksField::from_canonical_u64(x)
}

pub fn goldilocks_to_fe<F: PrimeField>(x: GoldilocksField) -> F {
    F::from(x.to_canonical_u64())
}

pub fn goldilocks_decompose<F: PrimeField>(x: F) -> [F; 4] {
    let mut limbs = vec![];
    let mut x = fe_to_big(x);
    for _ in 0..4 {
        let (q, r) = x.div_rem(&BigUint::from(GOLDILOCKS_MODULUS));
        let mut r_digits = r.to_u64_digits();
        r_digits.resize(1, 0);
        limbs.push(F::from(r_digits[0]));
        x = q;
    }
    limbs.try_into().unwrap()
}
