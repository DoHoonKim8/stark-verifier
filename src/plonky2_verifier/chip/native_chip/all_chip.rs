use halo2_proofs::{
    circuit::{AssignedCell, Layouter},
    halo2curves::ff::PrimeField,
    plonk::{ConstraintSystem, Error},
};
use plonky2::hash::hashing::SPONGE_WIDTH;

use crate::plonky2_verifier::{bn245_poseidon::constants::T_BN254_POSEIDON, context::RegionCtx};

use super::{
    arithmetic_chip::{ArithmeticChip, ArithmeticChipConfig},
    poseidon_bn254_chip::{PoseidonBn254Chip, PoseidonBn254ChipConfig},
};

#[derive(Clone, Debug)]
pub struct AllChipConfig<F: PrimeField> {
    pub arithmetic_config: ArithmeticChipConfig<F>,
    pub poseidon_config: PoseidonBn254ChipConfig<F>,
}

impl<F: PrimeField> AllChipConfig<F> {
    pub fn configure(meta: &mut ConstraintSystem<F>) -> Self {
        let arithmetic_config = ArithmeticChipConfig::configure(meta);
        let poseidon_config = PoseidonBn254ChipConfig::configure(meta);
        Self {
            arithmetic_config,
            poseidon_config,
        }
    }
}

#[derive(Clone, Debug)]
pub struct AllChip<F: PrimeField> {
    config: AllChipConfig<F>,
}

impl<F: PrimeField> AllChip<F> {
    pub fn new(config: &AllChipConfig<F>) -> Self {
        Self {
            config: config.clone(),
        }
    }

    pub fn arithmetic_chip(&self) -> ArithmeticChip<F> {
        ArithmeticChip::new(&self.config.arithmetic_config)
    }

    pub fn poseidon_chip(&self) -> PoseidonBn254Chip<F> {
        PoseidonBn254Chip::new(&self.config.poseidon_config)
    }

    pub fn permute(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        state: [AssignedCell<F, F>; SPONGE_WIDTH],
    ) -> Result<[AssignedCell<F, F>; SPONGE_WIDTH], halo2_proofs::plonk::Error> {
        let arithmetic_chip = self.arithmetic_chip();
        let poseidon_chip = self.poseidon_chip();
        let zero = arithmetic_chip.assign_constant(ctx, F::ZERO)?;
        let offset_start = ctx.offset();

        // compose input
        let mut encoded_state = state
            .chunks(3)
            .map(|chunk| {
                let composed = arithmetic_chip.pack(ctx, chunk.to_vec().try_into().unwrap())?;
                Ok(composed)
            })
            .collect::<Result<Vec<_>, Error>>()?;
        encoded_state.resize(T_BN254_POSEIDON, zero.clone());
        let offset_end_compose = ctx.offset();

        // aplly permutation
        ctx.set_offset(offset_start);
        let output_state = poseidon_chip.apply_permute(ctx, encoded_state.try_into().unwrap())?;
        let offset_end_permute = ctx.offset();

        // decompose output
        ctx.set_offset(offset_end_compose);
        let decoded_state = output_state[0..4]
            .iter()
            .flat_map(|x| arithmetic_chip.unpack(ctx, x).unwrap())
            .collect::<Vec<_>>();
        let offset_end_decompose = ctx.offset();

        let max_offset = offset_end_decompose.max(offset_end_permute);
        ctx.set_offset(max_offset);
        Ok(decoded_state.try_into().unwrap())
    }

    pub fn load_table(
        &self,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), halo2_proofs::plonk::Error> {
        self.arithmetic_chip().load_table(layouter)
    }
}

#[cfg(test)]
mod tests {
    use halo2_proofs::{
        circuit::{floor_planner::V1, Layouter},
        dev::MockProver,
        halo2curves::bn256::Fr,
        plonk::{Circuit, ConstraintSystem, Error},
    };

    use crate::plonky2_verifier::chip::native_chip::test_utils::test_verify_on_contract;

    use super::AllChipConfig;

    #[derive(Clone, Default)]
    pub struct TestCircuit;

    impl Circuit<Fr> for TestCircuit {
        type Config = AllChipConfig<Fr>;
        type FloorPlanner = V1;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
            AllChipConfig::<Fr>::configure(meta)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fr>,
        ) -> Result<(), Error> {
            let chip = super::AllChip::new(&config);
            chip.load_table(&mut layouter)?;
            Ok(())
        }
    }

    #[test]
    fn test_all_chip_on_chain_verification() {
        const DEGREE: u32 = 17;
        let circuit = TestCircuit;
        let instance = vec![];
        let mock_prover = MockProver::run(DEGREE, &circuit, vec![instance.clone()]).unwrap();
        mock_prover.assert_satisfied();
        test_verify_on_contract(DEGREE, &circuit, &instance);
    }
}
