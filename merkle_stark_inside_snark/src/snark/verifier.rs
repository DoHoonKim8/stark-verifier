use crate::snark::goldilocks::GoldilocksField;
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{floor_planner::V1, *},
    plonk::*,
};
use halo2wrong_ecc::{
    maingate::{MainGate, MainGateConfig, RangeChip, RangeConfig},
    EccConfig,
};
use poseidon::Spec;
use std::marker::PhantomData;

#[derive(Clone)]
pub struct VerifierConfig<F: FieldExt> {
    main_gate_config: MainGateConfig,
    range_config: RangeConfig,
    _marker: PhantomData<F>,
}

impl<F: FieldExt> VerifierConfig<F> {
    pub fn new(
        meta: &mut ConstraintSystem<F>,
        composition_bits: Vec<usize>,
        overflow_bits: Vec<usize>,
    ) -> Self {
        let main_gate_config = MainGate::<F>::configure(meta);
        let range_config =
            RangeChip::<F>::configure(meta, &main_gate_config, composition_bits, overflow_bits);
        VerifierConfig {
            main_gate_config,
            range_config,
            _marker: PhantomData,
        }
    }

    pub fn ecc_chip_config(&self) -> EccConfig {
        EccConfig::new(self.range_config.clone(), self.main_gate_config.clone())
    }
}

#[derive(Clone)]
struct Verifier {}

impl Circuit<GoldilocksField> for Verifier {
    type Config = VerifierConfig<GoldilocksField>;
    type FloorPlanner = V1;

    fn without_witnesses(&self) -> Self {
        todo!()
    }

    fn configure(meta: &mut ConstraintSystem<GoldilocksField>) -> Self::Config {
        todo!()
    }

    fn synthesize(
        &self,
        config: Self::Config,
        layouter: impl Layouter<GoldilocksField>,
    ) -> Result<(), Error> {
        todo!()
    }
}
