use std::ops::Range;

use halo2_proofs::{arithmetic::Field, plonk::Error};
use halo2curves::{goldilocks::fp::Goldilocks, FieldExt};
use halo2wrong::RegionCtx;

use crate::snark::{
    chip::{
        goldilocks_chip::GoldilocksChipConfig,
        goldilocks_extension_algebra_chip::AssignedExtensionAlgebra,
        plonk::gates::poseidon::{MDS_MATRIX_CIRC, MDS_MATRIX_DIAG},
    },
    types::assigned::{AssignedExtensionFieldValue, AssignedHashValues},
    T,
};

use super::CustomGateConstrainer;

#[derive(Clone, Debug, Default)]
pub struct PoseidonMDSGateConstrainer;

impl PoseidonMDSGateConstrainer {
    pub fn wires_input(i: usize) -> Range<usize> {
        assert!(i < T);
        i * 2..(i + 1) * 2
    }

    pub fn wires_output(i: usize) -> Range<usize> {
        assert!(i < T);
        (T + i) * 2..(T + i + 1) * 2
    }

    fn mds_row_shf<F: FieldExt>(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        goldilocks_chip_config: &GoldilocksChipConfig<F>,
        row: usize,
        state: &Vec<AssignedExtensionAlgebra<F>>,
    ) -> Result<AssignedExtensionAlgebra<F>, Error> {
        debug_assert!(row < T);
        let goldilocks_extension_chip = self.goldilocks_extension_chip(goldilocks_chip_config);
        let goldilocks_extension_algebra_chip =
            self.goldilocks_extension_algebra_chip(goldilocks_chip_config);
        let mut res = goldilocks_extension_algebra_chip.zero_ext_algebra(ctx)?;

        for i in 0..T {
            let c = goldilocks_extension_chip.constant_extension(
                ctx,
                &[Goldilocks::from(MDS_MATRIX_CIRC[i]), Goldilocks::zero()],
            )?;
            res = goldilocks_extension_algebra_chip.scalar_mul_add_ext_algebra(
                ctx,
                &c,
                &state[(i + row) % T],
                &res,
            )?;
        }
        let c = goldilocks_extension_chip.constant_extension(
            ctx,
            &[Goldilocks::from(MDS_MATRIX_DIAG[row]), Goldilocks::zero()],
        )?;
        res = goldilocks_extension_algebra_chip.scalar_mul_add_ext_algebra(
            ctx,
            &c,
            &state[row],
            &res,
        )?;

        Ok(res)
    }

    fn mds_layer<F: FieldExt>(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        goldilocks_chip_config: &GoldilocksChipConfig<F>,
        state: &Vec<AssignedExtensionAlgebra<F>>,
    ) -> Vec<AssignedExtensionAlgebra<F>> {
        let mut result = vec![];
        for i in 0..T {
            result.push(
                self.mds_row_shf(ctx, goldilocks_chip_config, i, state)
                    .unwrap(),
            );
        }
        result
    }
}

impl<F: FieldExt> CustomGateConstrainer<F> for PoseidonMDSGateConstrainer {
    fn eval_unfiltered_constraint(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        goldilocks_chip_config: &GoldilocksChipConfig<F>,
        _local_constants: &[AssignedExtensionFieldValue<F, 2>],
        local_wires: &[AssignedExtensionFieldValue<F, 2>],
        _public_inputs_hash: &AssignedHashValues<F>,
    ) -> Result<Vec<AssignedExtensionFieldValue<F, 2>>, Error> {
        let goldilocks_extension_algebra_chip =
            self.goldilocks_extension_algebra_chip(goldilocks_chip_config);
        let inputs = (0..T)
            .map(|i| self.get_local_ext_algebra(local_wires, Self::wires_input(i)))
            .collect::<Vec<_>>();
        let computed_outputs = self.mds_layer(ctx, goldilocks_chip_config, &inputs);

        let constraints = (0..T)
            .map(|i| self.get_local_ext_algebra(local_wires, Self::wires_output(i)))
            .zip(computed_outputs)
            .flat_map(|(out, computed_out)| {
                goldilocks_extension_algebra_chip
                    .sub_ext_algebra(ctx, &out, &computed_out)
                    .unwrap()
                    .to_ext_array()
            })
            .collect();
        Ok(constraints)
    }
}

#[cfg(test)]
mod tests {
    use super::PoseidonMDSGateConstrainer;
    use crate::snark::chip::plonk::gates::gate_test::test_custom_gate;
    use plonky2::gates::poseidon_mds::PoseidonMdsGate;

    #[test]
    fn test_poseidon_mds_gate() {
        let plonky2_gate = PoseidonMdsGate::new();
        let halo2_gate = PoseidonMDSGateConstrainer;
        test_custom_gate(plonky2_gate, halo2_gate, 17);
    }
}
