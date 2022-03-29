use halo2_proofs::{
    arithmetic::FieldExt,
    plonk::{ConstraintSystem, Selector},
};

#[derive(Debug, Clone, Copy)]
pub struct SelectionVector<const REG_COUNT: usize> {
    /// Row t
    pub row: ExeRow<REG_COUNT>,
    // Row t+1
    pub row_next: ExeRow<REG_COUNT>,
}

impl<const REG_COUNT: usize> SelectionVector<REG_COUNT> {
    pub fn new<F: FieldExt>(
        meta: &mut ConstraintSystem<F>,
    ) -> SelectionVector<REG_COUNT> {
        SelectionVector {
            row: ExeRow::new(meta),
            row_next: ExeRow::new(meta),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ExeRow<const REG_COUNT: usize> {
    pub pc: Selector,
    pub immediate: Selector,
    pub regs: [Selector; REG_COUNT],
    pub flag: Selector,
    pub address: Selector,
    pub value: Selector,
}

impl<const REG_COUNT: usize> ExeRow<REG_COUNT> {
    pub fn new<F: FieldExt>(meta: &mut ConstraintSystem<F>) -> ExeRow<REG_COUNT> {
        ExeRow {
            pc: meta.selector(),
            immediate: meta.selector(),
            regs: [0; REG_COUNT].map(|_| meta.selector()),
            flag: meta.selector(),
            address: meta.selector(),
            value: meta.selector(),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct TempVarSelectors<const REG_COUNT: usize> {
    pub a: SelectionVector<REG_COUNT>,
    pub b: SelectionVector<REG_COUNT>,
    pub c: SelectionVector<REG_COUNT>,
    pub d: SelectionVector<REG_COUNT>,
    pub out: SelectionVector<REG_COUNT>,
    pub ch: SelectionVector<REG_COUNT>,
}

impl<const REG_COUNT: usize> TempVarSelectors<REG_COUNT> {
    pub fn new<F: FieldExt>(
        meta: &mut ConstraintSystem<F>,
    ) -> TempVarSelectors<REG_COUNT> {
        TempVarSelectors {
            a: SelectionVector::new(meta),
            b: SelectionVector::new(meta),
            c: SelectionVector::new(meta),
            d: SelectionVector::new(meta),
            out: SelectionVector::new(meta),
            ch: SelectionVector::new(meta),
        }
    }
}
