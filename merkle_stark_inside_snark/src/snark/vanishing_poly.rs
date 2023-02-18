use core::iter;
use halo2_proofs::{arithmetic::Field, plonk::Error};
use halo2curves::goldilocks::fp::Goldilocks;
use halo2wrong::RegionCtx;
use halo2wrong_maingate::{AssignedValue, MainGateConfig};
use itertools::Itertools;

use super::{
    types::{
        assigned::{AssignedExtensionFieldValue, AssignedHashValues},
        common_data::CommonData,
    },
    verifier_circuit::Verifier,
};

impl Verifier {
    pub fn eval_vanishing_poly(
        &self,
        ctx: &mut RegionCtx<'_, Goldilocks>,
        main_gate_config: &MainGateConfig,
        common_data: &CommonData,
        x: &AssignedExtensionFieldValue<Goldilocks, 2>,
        x_pow_deg: &AssignedExtensionFieldValue<Goldilocks, 2>,
        local_constants: &[AssignedExtensionFieldValue<Goldilocks, 2>],
        local_wires: &[AssignedExtensionFieldValue<Goldilocks, 2>],
        public_inputs_hash: &AssignedHashValues<Goldilocks>,
        local_zs: &[AssignedExtensionFieldValue<Goldilocks, 2>],
        next_zs: &[AssignedExtensionFieldValue<Goldilocks, 2>],
        partial_products: &[AssignedExtensionFieldValue<Goldilocks, 2>],
        s_sigmas: &[AssignedExtensionFieldValue<Goldilocks, 2>],
        betas: &[AssignedValue<Goldilocks>],
        gammas: &[AssignedValue<Goldilocks>],
        alphas: &[AssignedValue<Goldilocks>],
    ) -> Result<Vec<AssignedExtensionFieldValue<Goldilocks, 2>>, Error> {
        let max_degree = common_data.quotient_degree_factor;
        let num_prods = common_data.num_partial_products;

        let constraint_terms = self.eval_gate_constraints(
            ctx,
            main_gate_config,
            common_data,
            local_constants,
            local_wires,
        )?;

        // The L_0(x) (Z(x) - 1) vanishing terms.
        let mut vanishing_z_1_terms = Vec::new();
        // The terms checking the partial products.
        let mut vanishing_partial_products_terms = Vec::new();

        let l_0_x = self.eval_l_0_x(ctx, main_gate_config, common_data.degree(), x, x_pow_deg)?;

        let mut s_ids = vec![];
        for j in 0..common_data.config.num_routed_wires {
            let k = common_data.k_is[j];
            s_ids.push(self.scalar_mul(ctx, main_gate_config, x, k)?);
        }

        for i in 0..common_data.config.num_challenges {
            let z_x = &local_zs[i];
            let z_gx = &next_zs[i];

            vanishing_z_1_terms.push(self.mul_sub_extension(
                ctx,
                main_gate_config,
                &l_0_x,
                z_x,
                &l_0_x,
            )?);

            let mut numerator_values = vec![];
            let mut denominator_values = vec![];

            for j in 0..common_data.config.num_routed_wires {
                let wire_value = &local_wires[j];
                let beta = self.convert_to_extension(ctx, main_gate_config, &betas[i])?;
                let gamma = self.convert_to_extension(ctx, main_gate_config, &gammas[i])?;

                // The numerator is `beta * s_id + wire_value + gamma`, and the denominator is
                // `beta * s_sigma + wire_value + gamma`.
                let wire_value_plus_gamma =
                    self.add_extension(ctx, main_gate_config, wire_value, &gamma)?;
                let numerator = self.mul_add_extension(
                    ctx,
                    main_gate_config,
                    &beta,
                    &s_ids[j],
                    &wire_value_plus_gamma,
                )?;
                let denominator = self.mul_add_extension(
                    ctx,
                    main_gate_config,
                    &beta,
                    &s_sigmas[j],
                    &wire_value_plus_gamma,
                )?;
                numerator_values.push(numerator);
                denominator_values.push(denominator);
            }

            // The partial products considered for this iteration of `i`.
            let current_partial_products = &partial_products[i * num_prods..(i + 1) * num_prods];
            // Check the quotient partial products.
            let partial_product_checks = self.check_partial_products(
                ctx,
                main_gate_config,
                &numerator_values,
                &denominator_values,
                current_partial_products,
                z_x,
                z_gx,
                max_degree,
            )?;
            vanishing_partial_products_terms.extend(partial_product_checks);
        }

        let vanishing_terms = [
            vanishing_z_1_terms,
            vanishing_partial_products_terms,
            constraint_terms,
        ]
        .concat();

        todo!()
    }

    fn eval_gate_constraints(
        &self,
        ctx: &mut RegionCtx<'_, Goldilocks>,
        main_gate_config: &MainGateConfig,
        common_data: &CommonData,
        local_constants: &[AssignedExtensionFieldValue<Goldilocks, 2>],
        local_wires: &[AssignedExtensionFieldValue<Goldilocks, 2>],
    ) -> Result<Vec<AssignedExtensionFieldValue<Goldilocks, 2>>, Error> {
        let zero_extension = self.zero_extension(ctx, main_gate_config)?;
        let mut all_gate_constraints = vec![zero_extension; common_data.num_gate_constraints];
        for (i, gate) in common_data.gates.iter().enumerate() {
            let selector_index = common_data.selectors_info.selector_indices[i];
            gate.0.eval_filtered_constraint(
                &self,
                ctx,
                main_gate_config,
                local_constants,
                local_wires,
                i,
                selector_index,
                common_data.selectors_info.groups[selector_index].clone(),
                &mut all_gate_constraints,
            )?;
        }
        Ok(all_gate_constraints)
    }

    fn eval_l_0_x(
        &self,
        ctx: &mut RegionCtx<'_, Goldilocks>,
        main_gate_config: &MainGateConfig,
        n: usize,
        x: &AssignedExtensionFieldValue<Goldilocks, 2>,
        x_pow_n: &AssignedExtensionFieldValue<Goldilocks, 2>,
    ) -> Result<AssignedExtensionFieldValue<Goldilocks, 2>, Error> {
        // L_0(x) = (x^n - 1) / (n * (x - 1))
        //        = (x_pow_deg - 1) / (n * (x - 1))
        let one_extension = self.one_extension(ctx, main_gate_config)?;
        let neg_one = self.constant_extension(
            ctx,
            main_gate_config,
            &[-Goldilocks::one(), Goldilocks::zero()],
        )?;
        let zero_poly = self.sub_extension(ctx, main_gate_config, &x_pow_n, &one_extension)?;
        let denominator = self.arithmetic_extension(
            ctx,
            main_gate_config,
            Goldilocks::from(n as u64),
            Goldilocks::from(n as u64),
            &x,
            &one_extension,
            &neg_one,
        )?;
        self.div_extension(ctx, main_gate_config, &zero_poly, &denominator)
    }

    // \prod(g_i'(x))\phi_1(x) - \prod(f_i'(x))Z(x)
    // ..
    // \prod(g_i'(x))Z(gx) - \prod(f_i'(x))\phi_s(x)
    fn check_partial_products(
        &self,
        ctx: &mut RegionCtx<'_, Goldilocks>,
        main_gate_config: &MainGateConfig,
        numerators: &[AssignedExtensionFieldValue<Goldilocks, 2>],
        denominators: &[AssignedExtensionFieldValue<Goldilocks, 2>],
        partials: &[AssignedExtensionFieldValue<Goldilocks, 2>],
        z_x: &AssignedExtensionFieldValue<Goldilocks, 2>,
        z_gx: &AssignedExtensionFieldValue<Goldilocks, 2>,
        max_degree: usize,
    ) -> Result<Vec<AssignedExtensionFieldValue<Goldilocks, 2>>, Error> {
        let product_accs = iter::once(z_x)
            .chain(partials.iter())
            .chain(iter::once(z_gx));
        let chunk_size = max_degree;
        numerators
            .chunks(chunk_size)
            .zip_eq(denominators.chunks(chunk_size))
            .zip_eq(product_accs.tuple_windows())
            .map(|((nume_chunk, denom_chunk), (prev_acc, next_acc))| {
                let nume_product =
                    self.mul_many_extension(ctx, main_gate_config, nume_chunk.to_vec())?;
                let denom_product =
                    self.mul_many_extension(ctx, main_gate_config, denom_chunk.to_vec())?;
                let next_acc_deno =
                    self.mul_extension(ctx, main_gate_config, next_acc, &denom_product)?;
                // Assert that next_acc * deno_product = prev_acc * nume_product.
                self.mul_sub_extension(
                    ctx,
                    main_gate_config,
                    prev_acc,
                    &nume_product,
                    &next_acc_deno,
                )
            })
            .collect()
    }
}
