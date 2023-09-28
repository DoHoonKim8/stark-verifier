use std::ops::Range;
use std::print;

use halo2_proofs::arithmetic::Field;
use halo2_proofs::plonk::Error;
use halo2curves::goldilocks::fp::Goldilocks;
use halo2curves::FieldExt;
use halo2wrong::RegionCtx;
use plonky2::gates::poseidon_mds::PoseidonMdsGate;
use plonky2::hash::hash_types::RichField;
use plonky2::{field::goldilocks_field::GoldilocksField, gates::gate::GateRef};

use self::arithmetic_extension::ArithmeticExtensionGateConstrainer;
use self::base_sum::BaseSumGateConstrainer;
use self::comparison_gate::ComparisonGateContainer;
use self::coset_interpolation_gate::CosetInterpolationGateConstrainer;
use self::multiplication_extension::MulExtensionGateConstrainer;
use self::poseidon::PoseidonGateConstrainer;
use self::poseidon_mds::PoseidonMDSGateConstrainer;
use self::random_access::RandomAccessGateConstrainer;
use self::reducing::ReducingGateConstrainer;
use self::reducing_extension::ReducingExtensionGateConstrainer;
use self::u32_add_many::U32AddManyGateConstrainer;
use self::u32_arithmetic::U32ArithmeticGateConstrainer;
use self::{
    arithmetic::ArithmeticGateConstrainer, constant::ConstantGateConstrainer,
    noop::NoopGateConstrainer, public_input::PublicInputGateConstrainer,
};

use crate::snark::chip::goldilocks_chip::GoldilocksChipConfig;
use crate::snark::chip::goldilocks_extension_algebra_chip::{
    AssignedExtensionAlgebra, GoldilocksExtensionAlgebraChip,
};
use crate::snark::chip::goldilocks_extension_chip::GoldilocksExtensionChip;
use crate::snark::types::assigned::{AssignedExtensionFieldValue, AssignedHashValues};

/// Placeholder value to indicate that a gate doesn't use a selector polynomial.
const UNUSED_SELECTOR: usize = u32::MAX as usize;

pub mod arithmetic;
pub mod arithmetic_extension;
pub mod base_sum;
pub mod comparison_gate;
pub mod constant;
pub mod coset_interpolation_gate;
pub mod multiplication_extension;
pub mod noop;
pub mod poseidon;
pub mod poseidon_mds;
pub mod public_input;
pub mod random_access;
pub mod reducing;
pub mod reducing_extension;
pub mod u32_add_many;
pub mod u32_arithmetic;

/// Evaluate custom gate constraints in `plonk_zeta` inside maingate.
pub trait CustomGateConstrainer<F: FieldExt>: CustomGateConstrainerClone<F> {
    fn get_local_ext_algebra(
        &self,
        local_wires: &[AssignedExtensionFieldValue<F, 2>],
        wire_range: Range<usize>,
    ) -> AssignedExtensionAlgebra<F> {
        debug_assert_eq!(wire_range.len(), 2);
        let arr = local_wires[wire_range].to_vec().try_into().unwrap();
        AssignedExtensionAlgebra(arr)
    }

    fn goldilocks_extension_chip(
        &self,
        goldilocks_chip_config: &GoldilocksChipConfig<F>,
    ) -> GoldilocksExtensionChip<F> {
        GoldilocksExtensionChip::new(goldilocks_chip_config)
    }

    fn goldilocks_extension_algebra_chip(
        &self,
        goldilocks_chip_config: &GoldilocksChipConfig<F>,
    ) -> GoldilocksExtensionAlgebraChip<F> {
        GoldilocksExtensionAlgebraChip::new(goldilocks_chip_config)
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
            "BaseSumGate { num_limbs: 63 } + Base: 2" => {
                Self(Box::new(BaseSumGateConstrainer { num_limbs: 63 }))
            },
            "PoseidonGate(PhantomData<plonky2_field::goldilocks_field::GoldilocksField>)<WIDTH=12>" => {
                Self(Box::new(PoseidonGateConstrainer))
            },
            "PoseidonMdsGate(PhantomData<plonky2_field::goldilocks_field::GoldilocksField>)<WIDTH=12>" => {
                Self(Box::new(PoseidonMDSGateConstrainer))
            },
            "RandomAccessGate { bits: 1, num_copies: 20, num_extra_constants: 0, _phantom: PhantomData<plonky2_field::goldilocks_field::GoldilocksField> }<D=2>" => {
                Self(Box::new(RandomAccessGateConstrainer {
                    bits: 1,
                    num_copies: 20,
                    num_extra_constants: 0,
                }))
            },
            "RandomAccessGate { bits: 4, num_copies: 4, num_extra_constants: 2, _phantom: PhantomData<plonky2_field::goldilocks_field::GoldilocksField> }<D=2>" => {
                Self(Box::new(RandomAccessGateConstrainer {
                    bits: 4,
                    num_copies: 4,
                    num_extra_constants: 2,
                }))
            },
            "ReducingExtensionGate { num_coeffs: 32 }" => {
                Self(Box::new(ReducingExtensionGateConstrainer {
                    num_coeffs: 32,
                }))
            },
            "ReducingGate { num_coeffs: 43 }" => {
                Self(Box::new(ReducingGateConstrainer {
                    num_coeffs: 43,
                }))
            },
            "ArithmeticExtensionGate { num_ops: 10 }" => {
                Self(Box::new(ArithmeticExtensionGateConstrainer {
                    num_ops: 10
                }))
            },
            "MulExtensionGate { num_ops: 13 }" => {
                Self(Box::new(MulExtensionGateConstrainer {
                    num_ops: 13
                }))
            },
            "BaseSumGate { num_limbs: 4 } + Base: 2" => {
                Self(Box::new(BaseSumGateConstrainer {
                    num_limbs: 4
                }))
            },
            "PoseidonMdsGate(PhantomData)<WIDTH=12>" => {
                Self(Box::new(PoseidonMDSGateConstrainer))
            },
            "PoseidonGate(PhantomData)<WIDTH=12>" => {
                Self(Box::new(PoseidonGateConstrainer))
            },
            "RandomAccessGate { bits: 1, num_copies: 20, num_extra_constants: 0, _phantom: PhantomData }<D=2>" => {
                Self(Box::new(RandomAccessGateConstrainer {
                    bits: 1,
                    num_copies: 20,
                    num_extra_constants: 0,
                }))
            },
            "RandomAccessGate { bits: 4, num_copies: 4, num_extra_constants: 2, _phantom: PhantomData }<D=2>" => {
                Self(Box::new(RandomAccessGateConstrainer {
                    bits: 4,
                    num_copies: 4,
                    num_extra_constants: 2,
                }))
            },
            "BaseSumGate { num_limbs: 32 } + Base: 2" => {
                Self(Box::new(BaseSumGateConstrainer {
                    num_limbs: 32
                }))
            },
            "ComparisonGate { num_bits: 32, num_chunks: 16, _phantom: PhantomData<plonky2_field::goldilocks_field::GoldilocksField> }<D=2>" => {
                Self(Box::new(ComparisonGateContainer {
                    num_bits: 32,
                    num_chunks: 16,
                }))
            },
            "ComparisonGate { num_bits: 10, num_chunks: 5, _phantom: PhantomData<plonky2_field::goldilocks_field::GoldilocksField> }<D=2>" => {
                Self(Box::new(ComparisonGateContainer {
                    num_bits: 10,
                    num_chunks: 5,
                }))
            }
            "U32AddManyGate { num_addends: 2, num_ops: 5, _phantom: PhantomData<plonky2_field::goldilocks_field::GoldilocksField> }" => {
                Self(Box::new(U32AddManyGateConstrainer {
                    num_addends: 2,
                    num_ops: 5,
                }))
            },
            "U32AddManyGate { num_addends: 3, num_ops: 5, _phantom: PhantomData<plonky2_field::goldilocks_field::GoldilocksField> }" => {
                Self(Box::new(U32AddManyGateConstrainer {
                    num_addends: 3,
                    num_ops: 5,
                }))
            },
            "U32ArithmeticGate { num_ops: 3, _phantom: PhantomData<plonky2_field::goldilocks_field::GoldilocksField> }" => {
                Self(Box::new(U32ArithmeticGateConstrainer {
                    num_ops: 3,
                }))
            },
            "CosetInterpolationGate { subgroup_bits: 4, degree: 6, barycentric_weights: [17293822565076172801, 18374686475376656385, 18446744069413535745, 281474976645120, 17592186044416, 256, 18446744000695107601, 18446744065119617025, 1152921504338411520, 72057594037927936, 1048576, 18446462594437939201, 18446726477228539905, 18446744069414584065, 68719476720, 4294967296], _phantom: PhantomData<plonky2_field::goldilocks_field::GoldilocksField> }<D=2>" => {
                Self(Box::new(CosetInterpolationGateConstrainer {
                    subgroup_bits: 4,
                    degree: 6,
                    barycentric_weights: vec![
                        Goldilocks::from(17293822565076172801),
                        Goldilocks::from(18374686475376656385),
                        Goldilocks::from(18446744069413535745),
                        Goldilocks::from(281474976645120),
                        Goldilocks::from(17592186044416),
                        Goldilocks::from(256),
                        Goldilocks::from(18446744000695107601),
                        Goldilocks::from(18446744065119617025),
                        Goldilocks::from(1152921504338411520),
                        Goldilocks::from(72057594037927936),
                        Goldilocks::from(1048576),
                        Goldilocks::from(18446462594437939201),
                        Goldilocks::from(18446726477228539905),
                        Goldilocks::from(18446744069414584065),
                        Goldilocks::from(68719476720),
                        Goldilocks::from(4294967296),
                    ],
                }))
            },
            "U32AddManyGate { num_addends: 4, num_ops: 5, _phantom: PhantomData<plonky2_field::goldilocks_field::GoldilocksField> }" => {
                Self(Box::new(U32AddManyGateConstrainer {
                    num_addends: 4,
                    num_ops: 5,
                }))
            }
            s => {
                println!("{s}");
                unimplemented!()
            }
        }
    }
}

/// This trait is for cloning the boxed trait object.
pub trait CustomGateConstrainerClone<F: FieldExt> {
    fn clone_box(&self) -> Box<dyn CustomGateConstrainer<F>>;
}

impl<T, F: FieldExt> CustomGateConstrainerClone<F> for T
where
    T: CustomGateConstrainer<F> + Clone + 'static,
{
    fn clone_box(&self) -> Box<dyn CustomGateConstrainer<F>> {
        Box::new(self.clone())
    }
}

impl<F: FieldExt> Clone for Box<dyn CustomGateConstrainer<F>> {
    fn clone(&self) -> Self {
        self.clone_box()
    }
}
