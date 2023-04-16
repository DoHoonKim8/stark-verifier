use std::ops::Range;

use halo2_proofs::arithmetic::Field;
use halo2_proofs::plonk::Error;
use halo2curves::goldilocks::fp::Goldilocks;
use halo2curves::FieldExt;
use halo2wrong::RegionCtx;
use halo2wrong_maingate::MainGateConfig;
use plonky2::{field::goldilocks_field::GoldilocksField, gates::gate::GateRef};

use self::{
    arithmetic::ArithmeticGateConstrainer, constant::ConstantGateConstrainer,
    noop::NoopGateConstrainer, public_input::PublicInputGateConstrainer,
};

use crate::snark::chip::goldilocks_chip::GoldilocksChipConfig;
use crate::snark::chip::goldilocks_extension_chip::GoldilocksExtensionChip;
use crate::snark::types::assigned::{AssignedExtensionFieldValue, AssignedHashValues};

/// Placeholder value to indicate that a gate doesn't use a selector polynomial.
const UNUSED_SELECTOR: usize = u32::MAX as usize;

pub mod arithmetic;
pub mod constant;
pub mod noop;
pub mod public_input;

/// Represents Plonky2's cutom gate. Evaluate gate constraint in `plonk_zeta` inside halo2 circuit.
pub trait CustomGateConstrainer<F: FieldExt> {
    fn goldilocks_extension_chip(
        &self,
        goldilocks_chip_config: &GoldilocksChipConfig<F>,
    ) -> GoldilocksExtensionChip<F> {
        GoldilocksExtensionChip::new(goldilocks_chip_config)
    }

    fn eval_unfiltered_constraint(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        goldilocks_chip_config: &GoldilocksChipConfig<F>,
        local_constants: &[AssignedExtensionFieldValue<F, 2>],
        local_wires: &[AssignedExtensionFieldValue<F, 2>],
        public_inputs_hash: &AssignedHashValues<F>,
    ) -> Result<Vec<AssignedExtensionFieldValue<F, 2>>, Error>;

    /// In Plonky2, each custom gate's constraint is multiplied by filtering polynomial
    /// `j`th gate's constraint is filtered by f_j(x) = \prod_{k=0, k \neq j}^{n-1}(f(x) - k) where
    /// f(g^i) = j if jth gate is used in ith row
    fn eval_filtered_constraint(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        goldilocks_chip_config: &GoldilocksChipConfig<F>,
        mut local_constants: &[AssignedExtensionFieldValue<F, 2>],
        local_wires: &[AssignedExtensionFieldValue<F, 2>],
        public_inputs_hash: &AssignedHashValues<F>,
        row: usize,
        selector_index: usize,
        group_range: Range<usize>,
        num_selectors: usize,
        combined_gate_constraints: &mut [AssignedExtensionFieldValue<F, 2>],
    ) -> Result<(), Error> {
        let goldilocks_extension_chip = self.goldilocks_extension_chip(goldilocks_chip_config);
        // f(\zeta)
        let f_zeta = &local_constants[selector_index];
        // \prod_{k=0, k \neq j}^{n-1}(f(\zeta) - k)
        let terms = group_range
            .filter(|&i| i != row)
            .chain((num_selectors > 1).then_some(UNUSED_SELECTOR))
            .map(|i| {
                let k = goldilocks_extension_chip
                    .constant_extension(ctx, &[Goldilocks::from(i as u64), Goldilocks::zero()])?;
                goldilocks_extension_chip.sub_extension(ctx, &k, &f_zeta)
            })
            .collect::<Result<Vec<AssignedExtensionFieldValue<F, 2>>, Error>>()?;
        let filter = goldilocks_extension_chip.mul_many_extension(ctx, terms)?;

        local_constants = &local_constants[num_selectors..];
        let gate_constraints = self.eval_unfiltered_constraint(
            ctx,
            goldilocks_chip_config,
            local_constants,
            local_wires,
            public_inputs_hash,
        )?;
        for (acc, c) in combined_gate_constraints.iter_mut().zip(gate_constraints) {
            *acc = goldilocks_extension_chip.mul_add_extension(ctx, &filter, &c, acc)?;
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct CustomGateRef<F: FieldExt>(pub Box<dyn CustomGateConstrainer<F>>);

impl<F: FieldExt> From<&GateRef<GoldilocksField, 2>> for CustomGateRef<F> {
    fn from(value: &GateRef<GoldilocksField, 2>) -> Self {
        match value.0.id().as_str().trim_end() {
            "ArithmeticGate { num_ops: 20 }" => Self(Box::new(ArithmeticGateConstrainer {
                num_ops: value.0.num_ops(),
            })),
            "PublicInputGate" => Self(Box::new(PublicInputGateConstrainer)),
            "NoopGate" => Self(Box::new(NoopGateConstrainer)),
            "ConstantGate { num_consts: 2 }" => Self(Box::new(ConstantGateConstrainer {
                num_consts: value.0.num_constants(),
            })),
            s => {
                println!("{s}");
                unimplemented!()
            }
        }
    }
}

impl<F: FieldExt> Clone for Box<dyn CustomGateConstrainer<F>> {
    fn clone(&self) -> Self {
        Box::clone(&self)
    }
}
