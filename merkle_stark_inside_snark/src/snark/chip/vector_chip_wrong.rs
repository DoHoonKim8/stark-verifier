use halo2curves::FieldExt;
use halo2wrong_transcript::ecc::integer::{AssignedInteger, IntegerConfig};

pub struct VectorChip<
    W: FieldExt,
    N: FieldExt,
    const NUMBER_OF_LIMBS: usize,
    const BIT_LEN_LIMB: usize,
> {
    integer_chip_config: IntegerConfig,
    vector: Vec<AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>>,
}
