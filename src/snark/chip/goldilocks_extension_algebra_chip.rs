use halo2_proofs::plonk::Error;
use halo2curves::{goldilocks::fp::Goldilocks, FieldExt};
use halo2wrong::RegionCtx;

use crate::snark::types::assigned::AssignedExtensionFieldValue;

use super::{
    goldilocks_chip::GoldilocksChipConfig, goldilocks_extension_chip::GoldilocksExtensionChip,
};

#[derive(Clone, Debug)]
pub struct AssignedExtensionAlgebra<F: FieldExt>(pub [AssignedExtensionFieldValue<F, 2>; 2]);

impl<F: FieldExt> AssignedExtensionAlgebra<F> {
    pub fn to_ext_array(&self) -> [AssignedExtensionFieldValue<F, 2>; 2] {
        self.0.clone()
    }
}

pub struct GoldilocksExtensionAlgebraChip<F: FieldExt> {
    goldilocks_chip_config: GoldilocksChipConfig<F>,
}

impl<F: FieldExt> GoldilocksExtensionAlgebraChip<F> {
    pub fn new(goldilocks_chip_config: &GoldilocksChipConfig<F>) -> Self {
        Self {
            goldilocks_chip_config: goldilocks_chip_config.clone(),
        }
    }

    pub fn goldilocks_extension_chip(&self) -> GoldilocksExtensionChip<F> {
        GoldilocksExtensionChip::new(&self.goldilocks_chip_config)
    }

    pub fn zero_ext_algebra(
        &self,
        ctx: &mut RegionCtx<'_, F>,
    ) -> Result<AssignedExtensionAlgebra<F>, Error> {
        let goldilocks_extension_chip = self.goldilocks_extension_chip();
        let zero_extension = goldilocks_extension_chip.zero_extension(ctx)?;
        Ok(AssignedExtensionAlgebra([
            zero_extension.clone(),
            zero_extension,
        ]))
    }

    pub fn convert_to_ext_algebra(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        et: &AssignedExtensionFieldValue<F, 2>,
    ) -> Result<AssignedExtensionAlgebra<F>, Error> {
        let goldilocks_extension_chip = self.goldilocks_extension_chip();
        let zero_extension = goldilocks_extension_chip.zero_extension(ctx)?;
        let mut arr = vec![];
        arr.extend([et.clone(), zero_extension]);
        Ok(AssignedExtensionAlgebra(arr.try_into().unwrap()))
    }

    /// Returns `sum_{(a,b) in vecs} constant * a * b`.
    pub fn inner_product_extension(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        constant: Goldilocks,
        starting_acc: &AssignedExtensionFieldValue<F, 2>,
        pairs: &Vec<(
            AssignedExtensionFieldValue<F, 2>,
            AssignedExtensionFieldValue<F, 2>,
        )>,
    ) -> Result<AssignedExtensionFieldValue<F, 2>, Error> {
        let goldilocks_extension_chip = self.goldilocks_extension_chip();
        let mut acc = starting_acc.clone();
        for (a, b) in pairs {
            acc = goldilocks_extension_chip.arithmetic_extension(
                ctx,
                constant,
                Goldilocks::from(1),
                a,
                b,
                &acc,
            )?;
        }
        Ok(acc)
    }

    /// Returns `a * b + c`, where `b, c` are in the extension algebra and `a` in the extension field.
    pub fn scalar_mul_add_ext_algebra(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        a: &AssignedExtensionFieldValue<F, 2>,
        b: &AssignedExtensionAlgebra<F>,
        c: &AssignedExtensionAlgebra<F>,
    ) -> Result<AssignedExtensionAlgebra<F>, Error> {
        let goldilocks_extension_chip = self.goldilocks_extension_chip();
        let mut res = c.clone();
        for i in 0..2 {
            res.0[i] = goldilocks_extension_chip.mul_add_extension(ctx, a, &b.0[i], &c.0[i])?;
        }
        Ok(res)
    }

    /// Returns `a * b`, where `b` is in the extension algebra and `a` in the extension field.
    pub fn scalar_mul_ext_algebra(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        a: &AssignedExtensionFieldValue<F, 2>,
        b: &AssignedExtensionAlgebra<F>,
    ) -> Result<AssignedExtensionAlgebra<F>, Error> {
        let zero = self.zero_ext_algebra(ctx)?;
        self.scalar_mul_add_ext_algebra(ctx, a, b, &zero)
    }

    /// Returns `a * b + c`.
    pub fn mul_add_ext_algebra(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        a: &AssignedExtensionAlgebra<F>,
        b: &AssignedExtensionAlgebra<F>,
        c: &AssignedExtensionAlgebra<F>,
    ) -> Result<AssignedExtensionAlgebra<F>, Error> {
        let w = GoldilocksExtensionChip::<F>::w();
        let mut inner = vec![vec![]; 2];
        let mut inner_w = vec![vec![]; 2];
        for i in 0..2 {
            for j in 0..2 - i {
                inner[(i + j) % 2].push((a.0[i].clone(), b.0[j].clone()));
            }
            for j in 2 - i..2 {
                inner_w[(i + j) % 2].push((a.0[i].clone(), b.0[j].clone()));
            }
        }
        let res = inner_w
            .into_iter()
            .zip(inner)
            .zip(c.0.clone())
            .map(|((pairs_w, pairs), ci)| {
                let acc = self.inner_product_extension(ctx, w, &ci, &pairs_w).unwrap();
                self.inner_product_extension(ctx, Goldilocks::from(1), &acc, &pairs)
            })
            .collect::<Result<Vec<_>, Error>>()?;

        Ok(AssignedExtensionAlgebra(res.try_into().unwrap()))
    }

    /// Returns `a * b`.
    pub fn mul_ext_algebra(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        a: &AssignedExtensionAlgebra<F>,
        b: &AssignedExtensionAlgebra<F>,
    ) -> Result<AssignedExtensionAlgebra<F>, Error> {
        let zero = self.zero_ext_algebra(ctx)?;
        self.mul_add_ext_algebra(ctx, a, b, &zero)
    }

    pub fn sub_ext_algebra(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        a: &AssignedExtensionAlgebra<F>,
        b: &AssignedExtensionAlgebra<F>,
    ) -> Result<AssignedExtensionAlgebra<F>, Error> {
        let goldilocks_extension_chip = self.goldilocks_extension_chip();
        let mut res = a.clone();
        for i in 0..2 {
            res.0[i] = goldilocks_extension_chip.sub_extension(ctx, &a.0[i], &b.0[i])?;
        }
        Ok(res)
    }
}
