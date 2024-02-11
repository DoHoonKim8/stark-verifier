use std::collections::HashMap;

use halo2_proofs::{
    circuit::{AssignedCell, Cell, Region, Value},
    halo2curves::ff::PrimeField,
    plonk::{Advice, Column, Error, Fixed, Selector},
};
use halo2wrong_maingate::fe_to_big;
use num_bigint::BigUint;

#[derive(Debug)]
pub struct RegionCtx<'a, F: PrimeField> {
    region: Region<'a, F>,
    offset: usize,
    contants: HashMap<BigUint, AssignedCell<F, F>>,
}

impl<'a, F: PrimeField> RegionCtx<'a, F> {
    pub fn new(region: Region<'a, F>, offset: usize) -> RegionCtx<'a, F> {
        RegionCtx {
            region,
            offset,
            contants: HashMap::new(),
        }
    }

    pub fn offset(&self) -> usize {
        self.offset
    }

    pub fn set_offset(&mut self, offset: usize) {
        self.offset = offset
    }

    pub fn into_region(self) -> Region<'a, F> {
        self.region
    }

    pub fn assign_fixed<A, AR>(
        &mut self,
        annotation: A,
        column: Column<Fixed>,
        value: F,
    ) -> Result<AssignedCell<F, F>, Error>
    where
        A: Fn() -> AR,
        AR: Into<String>,
    {
        self.region
            .assign_fixed(annotation, column, self.offset, || Value::known(value))
    }

    pub fn register_fixed(&mut self, value: F, cell: AssignedCell<F, F>) {
        self.contants.insert(fe_to_big(value), cell);
    }

    pub fn clear_fixed(&mut self) {
        self.contants.clear();
    }

    pub fn get_fixed(&self, value: &F) -> Option<&AssignedCell<F, F>> {
        self.contants.get(&fe_to_big(*value))
    }

    pub fn assign_advice<A, AR>(
        &mut self,
        annotation: A,
        column: Column<Advice>,
        value: Value<F>,
    ) -> Result<AssignedCell<F, F>, Error>
    where
        A: Fn() -> AR,
        AR: Into<String>,
    {
        self.region
            .assign_advice(annotation, column, self.offset, || value)
    }

    pub fn constrain_equal(&mut self, cell_0: Cell, cell_1: Cell) -> Result<(), Error> {
        self.region.constrain_equal(cell_0, cell_1)
    }

    pub fn enable(&mut self, selector: Selector) -> Result<(), Error> {
        selector.enable(&mut self.region, self.offset)
    }

    pub fn next(&mut self) {
        self.offset += 1
    }
}
