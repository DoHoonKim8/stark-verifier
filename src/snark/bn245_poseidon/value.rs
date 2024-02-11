use halo2_proofs::{circuit::Value, halo2curves::ff::PrimeField};
use num_bigint::BigUint;

use super::constants::{
    MDS_MATRIX_BG, ROUND_CONSTANTS_BG, R_F_BN254_POSEIDON, R_P_BN254_POSEIDON, T_BN254_POSEIDON,
};

pub fn bg_to_fe<F: PrimeField>(x: &BigUint) -> F {
    F::from_str_vartime(x.to_str_radix(10).as_str()).unwrap()
}

fn constant_layer<F: PrimeField>(state: &mut [Value<F>; T_BN254_POSEIDON], counter: &mut usize) {
    for i in 0..T_BN254_POSEIDON {
        state[i] = state[i] + Value::known(bg_to_fe::<F>(&ROUND_CONSTANTS_BG[*counter]));
        *counter += 1;
    }
}

fn sbox_layer<F: PrimeField>(state: &mut [Value<F>; T_BN254_POSEIDON]) {
    for i in 0..T_BN254_POSEIDON {
        state[i] = state[i] * state[i] * state[i] * state[i] * state[i];
    }
}

fn partial_sbox_layer<F: PrimeField>(state: &mut [Value<F>; T_BN254_POSEIDON]) {
    state[0] = state[0] * state[0] * state[0] * state[0] * state[0];
}

fn mds_layer<F: PrimeField>(state: &mut [Value<F>; T_BN254_POSEIDON]) {
    let mut new_state = [Value::known(F::from(0)); T_BN254_POSEIDON];
    for i in 0..T_BN254_POSEIDON {
        for j in 0..T_BN254_POSEIDON {
            new_state[i] =
                new_state[i] + state[j] * Value::known(bg_to_fe::<F>(&MDS_MATRIX_BG[i][j]));
        }
    }
    *state = new_state
}

pub fn partial_round_value<F: PrimeField>(
    state: &mut [Value<F>; T_BN254_POSEIDON],
    counter: &mut usize,
) {
    constant_layer(state, counter);
    partial_sbox_layer(state);
    mds_layer(state);
}

pub fn full_round_value<F: PrimeField>(
    state: &mut [Value<F>; T_BN254_POSEIDON],
    counter: &mut usize,
) {
    constant_layer(state, counter);
    sbox_layer(state);
    mds_layer(state);
}

pub fn permute_value<F: PrimeField>(state: &mut [Value<F>; T_BN254_POSEIDON]) {
    let mut counter = 0;
    for _ in 0..R_F_BN254_POSEIDON / 2 {
        full_round_value(state, &mut counter);
    }
    for _ in 0..R_P_BN254_POSEIDON {
        partial_round_value(state, &mut counter);
    }
    for _ in 0..R_F_BN254_POSEIDON / 2 {
        full_round_value(state, &mut counter);
    }
}

#[cfg(test)]
mod tests {
    use halo2_proofs::{circuit::Value, halo2curves::bn256::Fr};

    use crate::snark::bn245_poseidon::{
        constants::T_BN254_POSEIDON, native::permute_bn254_poseidon_native,
    };

    use super::permute_value;

    #[test]
    fn test_poseidon_correspondence_with_value() {
        let mut state_native = [Fr::from(0u64); T_BN254_POSEIDON];
        let mut state_value = state_native.map(|x| Value::known(x));
        permute_value(&mut state_value);
        permute_bn254_poseidon_native(&mut state_native);
        state_value
            .iter()
            .zip(state_native.iter())
            .for_each(|(x, y)| {
                x.map(|x| assert_eq!(x, *y));
            });
    }
}
