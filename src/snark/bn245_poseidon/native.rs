use halo2_proofs::{arithmetic::Field, halo2curves::bn256::Fr};
use halo2wrong_maingate::fe_to_big;
use plonky2::field::{
    goldilocks_field::GoldilocksField,
    types::{Field as Plonky2Field, PrimeField64},
};

use crate::snark::chip::native_chip::{arithmetic_chip::GOLDILOCKS_MODULUS, utils::goldilocks_decompose};

use super::constants::{
    MDS_MATRIX_FR, ROUND_CONSTANTS_FR, R_F_BN254_POSEIDON, R_P_BN254_POSEIDON, T_BN254_POSEIDON,
};

fn constant_layer(state: &mut [Fr; T_BN254_POSEIDON], counter: &mut usize) {
    for i in 0..T_BN254_POSEIDON {
        state[i] += ROUND_CONSTANTS_FR[*counter];
        *counter += 1;
    }
}

fn sbox_layer(state: &mut [Fr; T_BN254_POSEIDON]) {
    for i in 0..T_BN254_POSEIDON {
        state[i] = state[i].pow(&[5]);
    }
}

fn partial_sbox_layer(state: &mut [Fr; T_BN254_POSEIDON]) {
    state[0] = state[0].pow(&[5]);
}

fn mds_layer(state: &mut [Fr; T_BN254_POSEIDON]) {
    let mut new_state = [Fr::from(0); T_BN254_POSEIDON];
    for i in 0..T_BN254_POSEIDON {
        for j in 0..T_BN254_POSEIDON {
            new_state[i] += state[j] * &MDS_MATRIX_FR[i][j];
        }
    }
    *state = new_state
}

pub fn permute_bn254_poseidon_native(state: &mut [Fr; T_BN254_POSEIDON]) {
    let mut counter = 0;
    for _ in 0..R_F_BN254_POSEIDON / 2 {
        constant_layer(state, &mut counter);
        sbox_layer(state);
        mds_layer(state);
    }
    for _ in 0..R_P_BN254_POSEIDON {
        constant_layer(state, &mut counter);
        partial_sbox_layer(state);
        mds_layer(state);
    }
    for _ in 0..R_F_BN254_POSEIDON / 2 {
        constant_layer(state, &mut counter);
        sbox_layer(state);
        mds_layer(state);
    }
}

pub fn encode_fe(x: [GoldilocksField; 3]) -> Fr {
    let acc = x.iter().enumerate().fold(Fr::from(0u64), |acc, (i, x)| {
        acc + Fr::from(x.to_canonical_u64()) * Fr::from(GOLDILOCKS_MODULUS).pow(&[i as u64])
    });
    acc
}

pub fn decode_fe(x: Fr) -> [GoldilocksField; 3] {
    let decomposed = goldilocks_decompose(x).map(|x| {
        let mut digits = fe_to_big(x).to_u64_digits();
        digits.resize(1, 0);
        GoldilocksField::from_noncanonical_u64(digits[0])
    })[0..3]
        .to_vec();
    decomposed.try_into().unwrap()
}
