use halo2_proofs::plonk::Error;
use halo2curves::FieldExt;
use halo2wrong::RegionCtx;
use itertools::Itertools;

use crate::snark::{
    chip::goldilocks_chip::GoldilocksChipConfig,
    types::assigned::{AssignedExtensionFieldValue, AssignedHashValues},
};

use super::CustomGateConstrainer;

/// A gate for checking that a particular element of a list matches a given value.
#[derive(Clone, Debug)]
pub struct RandomAccessGateConstrainer {
    /// Number of bits in the index (log2 of the list size).
    pub bits: usize,

    /// How many separate copies are packed into one gate.
    pub num_copies: usize,

    /// Leftover wires are used as global scratch space to store constants.
    pub num_extra_constants: usize,
}

impl RandomAccessGateConstrainer {
    /// Length of the list being accessed.
    fn vec_size(&self) -> usize {
        1 << self.bits
    }

    /// For each copy, a wire containing the claimed index of the element.
    fn wire_access_index(&self, copy: usize) -> usize {
        debug_assert!(copy < self.num_copies);
        (2 + self.vec_size()) * copy
    }

    /// For each copy, a wire containing the element claimed to be at the index.
    fn wire_claimed_element(&self, copy: usize) -> usize {
        debug_assert!(copy < self.num_copies);
        (2 + self.vec_size()) * copy + 1
    }

    /// For each copy, wires containing the entire list.
    fn wire_list_item(&self, i: usize, copy: usize) -> usize {
        debug_assert!(i < self.vec_size());
        debug_assert!(copy < self.num_copies);
        (2 + self.vec_size()) * copy + 2 + i
    }

    fn start_extra_constants(&self) -> usize {
        (2 + self.vec_size()) * self.num_copies
    }

    fn wire_extra_constant(&self, i: usize) -> usize {
        debug_assert!(i < self.num_extra_constants);
        self.start_extra_constants() + i
    }

    /// All above wires are routed.
    fn num_routed_wires(&self) -> usize {
        self.start_extra_constants() + self.num_extra_constants
    }

    fn num_constraints(&self) -> usize {
        let constraints_per_copy = self.bits + 2;
        self.num_copies * constraints_per_copy + self.num_extra_constants
    }

    /// An intermediate wire where the prover gives the (purported) binary decomposition of the
    /// index.
    fn wire_bit(&self, i: usize, copy: usize) -> usize {
        debug_assert!(i < self.bits);
        debug_assert!(copy < self.num_copies);
        self.num_routed_wires() + copy * self.bits + i
    }
}

impl<F: FieldExt> CustomGateConstrainer<F> for RandomAccessGateConstrainer {
    fn eval_unfiltered_constraint(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        goldilocks_chip_config: &GoldilocksChipConfig<F>,
        local_constants: &[AssignedExtensionFieldValue<F, 2>],
        local_wires: &[AssignedExtensionFieldValue<F, 2>],
        _public_inputs_hash: &AssignedHashValues<F>,
    ) -> Result<Vec<AssignedExtensionFieldValue<F, 2>>, halo2_proofs::plonk::Error> {
        let goldilocks_extension_chip = self.goldilocks_extension_chip(goldilocks_chip_config);
        let two = goldilocks_extension_chip.two_extension(ctx)?;
        let mut constraints = Vec::with_capacity(self.num_constraints());

        for copy in 0..self.num_copies {
            let access_index = &local_wires[self.wire_access_index(copy)];
            let mut list_items = (0..self.vec_size())
                .map(|i| local_wires[self.wire_list_item(i, copy)].clone())
                .collect::<Vec<_>>();
            let claimed_element = &local_wires[self.wire_claimed_element(copy)];
            let bits = (0..self.bits)
                .map(|i| local_wires[self.wire_bit(i, copy)].clone())
                .collect::<Vec<_>>();

            // Assert that each bit wire value is indeed boolean.
            for b in &bits {
                constraints.push(goldilocks_extension_chip.mul_sub_extension(ctx, b, b, b)?);
            }

            // Assert that the binary decomposition was correct.
            let reconstructed_index =
                goldilocks_extension_chip.reduce_extension(ctx, &two, &bits)?;
            constraints.push(goldilocks_extension_chip.sub_extension(
                ctx,
                &reconstructed_index,
                access_index,
            )?);

            // Repeatedly fold the list, selecting the left or right item from each pair based on
            // the corresponding bit.
            for b in bits {
                list_items = list_items
                    .iter()
                    .tuples()
                    .map(|(x, y)| goldilocks_extension_chip.select(ctx, &b, y, x))
                    .collect::<Result<Vec<_>, Error>>()?;
            }

            // Check that the one remaining element after the folding is the claimed element.
            debug_assert_eq!(list_items.len(), 1);
            constraints.push(goldilocks_extension_chip.sub_extension(
                ctx,
                &list_items[0],
                &claimed_element,
            )?);
        }

        // Check the constant values.
        constraints.extend(
            (0..self.num_extra_constants)
                .map(|i| {
                    goldilocks_extension_chip.sub_extension(
                        ctx,
                        &local_constants[i],
                        &local_wires[self.wire_extra_constant(i)],
                    )
                })
                .collect::<Result<Vec<_>, Error>>()?,
        );

        Ok(constraints)
    }
}

#[cfg(test)]
mod tests {
    use super::RandomAccessGateConstrainer;
    use crate::snark::chip::plonk::gates::gate_test::test_custom_gate;
    use plonky2::{gates::random_access::RandomAccessGate, plonk::circuit_data::CircuitConfig};

    #[test]
    fn test_random_access_gate() {
        let config = CircuitConfig::default();
        let plonky2_gate = RandomAccessGate::new_from_config(&config, 2);
        let halo2_gate = RandomAccessGateConstrainer {
            bits: plonky2_gate.bits,
            num_copies: plonky2_gate.num_copies,
            num_extra_constants: plonky2_gate.num_extra_constants,
        };
        test_custom_gate(plonky2_gate, halo2_gate, 17);
    }
}
