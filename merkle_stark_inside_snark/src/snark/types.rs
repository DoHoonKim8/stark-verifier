/// This module contains Plonky2 types.
use serde::Deserialize;

#[derive(Deserialize, Debug)]
pub struct ProofWithPublicInputs {
    wires_cap: Vec<Vec<String>>,
    plonk_zs_partial_products_cap: Vec<Vec<String>>,
    quotient_polys_cap: Vec<Vec<String>>,

    openings_constants: Vec<Vec<String>>,
    openings_plonk_sigmas: Vec<Vec<String>>,
    openings_wires: Vec<Vec<String>>,
    openings_plonk_zs: Vec<Vec<String>>,
    openings_plonk_zs_next: Vec<Vec<String>>,
    openings_partial_products: Vec<Vec<String>>,
    openings_quotient_polys: Vec<Vec<String>>,

    fri_commit_phase_merkle_caps: Vec<Vec<Vec<String>>>,

    fri_query_init_constants_sigmas_v: Vec<Vec<String>>,
    fri_query_init_constants_sigmas_p: Vec<Vec<Vec<String>>>,
    fri_query_init_wires_v: Vec<Vec<String>>,
    fri_query_init_wires_p: Vec<Vec<Vec<String>>>,
    fri_query_init_zs_partial_v: Vec<Vec<String>>,
    fri_query_init_zs_partial_p: Vec<Vec<Vec<String>>>,
    fri_query_init_quotient_v: Vec<Vec<String>>,
    fri_query_init_quotient_p: Vec<Vec<Vec<String>>>,

    fri_query_step0_v: Vec<Vec<Vec<String>>>,
    fri_query_step0_p: Vec<Vec<Vec<String>>>,
    fri_query_step1_v: Vec<Vec<Vec<String>>>,
    fri_query_step1_p: Vec<Vec<Vec<String>>>,

    fri_final_poly_ext_v: Vec<Vec<String>>,
    fri_pow_witness: String,

    public_inputs: Vec<String>,
}

#[derive(Deserialize, Debug)]
pub struct HashOut {
    pub elements: [u64; 4],
}
