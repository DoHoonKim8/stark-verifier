use halo2_proofs::{halo2curves::ff::PrimeField, plonk::Error};
use halo2wrong_maingate::AssignedValue;
use plonky2::field::{goldilocks_field::GoldilocksField, types::Field};

use crate::plonky2_verifier::context::RegionCtx;

use super::goldilocks_chip::{GoldilocksChip, GoldilocksChipConfig};

pub struct VectorChip<F: PrimeField> {
    main_gate_config: GoldilocksChipConfig<F>,
    vector: Vec<AssignedValue<F>>,
}

impl<F: PrimeField> VectorChip<F> {
    pub fn new(main_gate_config: &GoldilocksChipConfig<F>, vector: Vec<AssignedValue<F>>) -> Self {
        Self {
            main_gate_config: main_gate_config.clone(),
            vector,
        }
    }

    fn main_gate(&self) -> GoldilocksChip<F> {
        GoldilocksChip::new(&self.main_gate_config)
    }

    pub fn access(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        index: &AssignedValue<F>,
    ) -> Result<AssignedValue<F>, Error> {
        let main_gate = self.main_gate();
        // this value will be used to check whether the index is in the bound
        let mut not_exists = main_gate.assign_constant(ctx, GoldilocksField::ONE)?;

        let zero = main_gate.assign_constant(ctx, GoldilocksField::ZERO)?;
        let mut element = zero.clone();
        for (i, v) in self.vector.iter().enumerate() {
            let assigned_i = main_gate.assign_constant(ctx, GoldilocksField(i as u64))?;
            let i_minus_index = main_gate.sub(ctx, &assigned_i, index)?;
            not_exists = main_gate.mul(ctx, &not_exists, &i_minus_index)?;

            let is_same_index = main_gate.is_equal(ctx, &i_minus_index, &zero)?;
            element = main_gate.select(ctx, v, &element, &is_same_index)?;
        }
        // if this fails, index is out of the bound, and will return error
        main_gate.assert_zero(ctx, &not_exists)?;
        Ok(element)
    }
}
