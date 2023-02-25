use std::ops::Range;

use halo2_proofs::{arithmetic::Field, plonk::Error};
use halo2curves::goldilocks::fp::Goldilocks;
use halo2wrong::RegionCtx;
use halo2wrong_maingate::MainGateConfig;
use plonky2::{field::goldilocks_field::GoldilocksField, gates::gate::GateRef};

use self::{
    arithmetic::ArithmeticGateConstrainer, constant::ConstantGateConstrainer,
    noop::NoopGateConstrainer, public_input::PublicInputGateConstrainer,
};

use super::{
    types::assigned::{AssignedExtensionFieldValue, AssignedHashValues},
    verifier_circuit::Verifier,
};

/// Placeholder value to indicate that a gate doesn't use a selector polynomial.
const UNUSED_SELECTOR: usize = u32::MAX as usize;

pub mod arithmetic;
pub mod constant;
pub mod noop;
pub mod public_input;

/// Represents Plonky2's cutom gate. Evaluate gate constraint in `plonk_zeta` inside halo2 circuit.
pub trait CustomGateConstrainer {
    fn eval_unfiltered_constraint(
        &self,
        verifier: &Verifier,
        ctx: &mut RegionCtx<'_, Goldilocks>,
        main_gate_config: &MainGateConfig,
        local_constants: &[AssignedExtensionFieldValue<Goldilocks, 2>],
        local_wires: &[AssignedExtensionFieldValue<Goldilocks, 2>],
        public_inputs_hash: &AssignedHashValues<Goldilocks>,
    ) -> Result<Vec<AssignedExtensionFieldValue<Goldilocks, 2>>, Error>;

    /// In Plonky2, each custom gate's constraint is multiplied by filtering polynomial
    /// `j`th gate's constraint is filtered by f_j(x) = \prod_{k=0, k \neq j}^{n-1}(f(x) - k) where
    /// f(g^i) = j if jth gate is used in ith row
    fn eval_filtered_constraint(
        &self,
        verifier: &Verifier,
        ctx: &mut RegionCtx<'_, Goldilocks>,
        main_gate_config: &MainGateConfig,
        mut local_constants: &[AssignedExtensionFieldValue<Goldilocks, 2>],
        local_wires: &[AssignedExtensionFieldValue<Goldilocks, 2>],
        public_inputs_hash: &AssignedHashValues<Goldilocks>,
        row: usize,
        selector_index: usize,
        group_range: Range<usize>,
        num_selectors: usize,
        combined_gate_constraints: &mut [AssignedExtensionFieldValue<Goldilocks, 2>],
    ) -> Result<(), Error> {
        // f(\zeta)
        let f_zeta = &local_constants[selector_index];
        // \prod_{k=0, k \neq j}^{n-1}(f(\zeta) - k)
        let terms = group_range
            .filter(|&i| i != row)
            .chain((num_selectors > 1).then_some(UNUSED_SELECTOR))
            .map(|i| {
                let k = verifier.constant_extension(
                    ctx,
                    main_gate_config,
                    &[Goldilocks::from(i as u64), Goldilocks::zero()],
                )?;
                verifier.sub_extension(ctx, main_gate_config, &k, &f_zeta)
            })
            .collect::<Result<Vec<AssignedExtensionFieldValue<Goldilocks, 2>>, Error>>()?;
        let filter = verifier.mul_many_extension(ctx, main_gate_config, terms)?;

        local_constants = &local_constants[num_selectors..];
        let gate_constraints = self.eval_unfiltered_constraint(
            verifier,
            ctx,
            main_gate_config,
            local_constants,
            local_wires,
            public_inputs_hash,
        )?;
        for (acc, c) in combined_gate_constraints.iter_mut().zip(gate_constraints) {
            *acc = verifier.mul_add_extension(ctx, main_gate_config, &filter, &c, acc)?;
        }
        Ok(())
    }
}

pub struct CustomGateRef(pub Box<dyn CustomGateConstrainer>);

impl From<&GateRef<GoldilocksField, 2>> for CustomGateRef {
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
