use std::ops::Range;

use halo2_proofs::{arithmetic::Field, plonk::Error};
use halo2curves::{goldilocks::fp::Goldilocks, FieldExt};
use halo2wrong::RegionCtx;

use crate::snark::{
    chip::{
        goldilocks_chip::GoldilocksChipConfig,
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
        state: &Vec<AssignedExtensionFieldValue<F, 2>>,
    ) -> Result<AssignedExtensionFieldValue<F, 2>, Error> {
        debug_assert!(row < T);
        let goldilocks_extension_chip = self.goldilocks_extension_chip(goldilocks_chip_config);
        let mut res = goldilocks_extension_chip.zero_extension(ctx)?;

        for i in 0..T {
            let c = goldilocks_extension_chip.constant_extension(
                ctx,
                &[Goldilocks::from(MDS_MATRIX_CIRC[i]), Goldilocks::zero()],
            )?;
            res = goldilocks_extension_chip.mul_add_extension(
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
        res = goldilocks_extension_chip.mul_add_extension(ctx, &c, &state[row], &res)?;

        Ok(res)
    }

    fn mds_layer<F: FieldExt>(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        goldilocks_chip_config: &GoldilocksChipConfig<F>,
        state: &Vec<AssignedExtensionFieldValue<F, 2>>,
    ) -> Vec<AssignedExtensionFieldValue<F, 2>> {
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
        local_constants: &[AssignedExtensionFieldValue<F, 2>],
        local_wires: &[AssignedExtensionFieldValue<F, 2>],
        public_inputs_hash: &AssignedHashValues<F>,
    ) -> Result<Vec<AssignedExtensionFieldValue<F, 2>>, Error> {
        let goldilocks_extension_chip = self.goldilocks_extension_chip(goldilocks_chip_config);
        let inputs = (0..T)
            .map(|i| local_wires[Self::wires_input(i)][0].clone())
            .collect::<Vec<_>>();
        let computed_outputs = self.mds_layer(ctx, goldilocks_chip_config, &inputs);

        let constraints = (0..T)
            .map(|i| local_wires[Self::wires_output(i)][0].clone())
            .zip(computed_outputs)
            .map(|(out, computed_out)| {
                goldilocks_extension_chip
                    .sub_extension(ctx, &out, &computed_out)
                    .unwrap()
            })
            .collect();
        Ok(constraints)
    }
}
