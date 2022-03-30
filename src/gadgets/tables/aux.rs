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

/// This corresponds to sch in the paper.
/// A selector value of 1 denotes an unchanged cell.
#[derive(Debug, Clone, Copy)]
pub struct UnChangedSelectors<const REG_COUNT: usize> {
    pub regs: [Selector; REG_COUNT],
    pub pc: Selector,
    pub flag: Selector,
}

impl<const REG_COUNT: usize> UnChangedSelectors<REG_COUNT> {
    pub fn new<F: FieldExt>(
        meta: &mut ConstraintSystem<F>,
    ) -> UnChangedSelectors<REG_COUNT> {
        UnChangedSelectors {
            regs: [0; REG_COUNT].map(|_| meta.selector()),
            pc: meta.selector(),
            flag: meta.selector(),
        }
    }
}

/// This corresponds to sout in the paper (page 24).
#[derive(Debug, Clone, Copy)]
pub struct OutSelectors<const REG_COUNT: usize> {
    /// logical
    pub and: Selector,
    pub xor: Selector,
    pub or: Selector,

    /// arithmetic
    pub sum: Selector,
    pub prog: Selector,
    pub ssum: Selector,
    pub sprod: Selector,
    pub mod_: Selector,

    pub shift: Selector,

    pub flag1: Selector,
    pub flag2: Selector,
    pub flag3: Selector,
    pub flag4: Selector,
}

impl<const REG_COUNT: usize> OutSelectors<REG_COUNT> {
    pub fn new<F: FieldExt>(
        meta: &mut ConstraintSystem<F>,
    ) -> OutSelectors<REG_COUNT> {
        OutSelectors {
            and: meta.selector(),
            xor: meta.selector(),
            or: meta.selector(),
            sum: meta.selector(),
            prog: meta.selector(),
            ssum: meta.selector(),
            sprod: meta.selector(),
            mod_: meta.selector(),
            shift: meta.selector(),
            flag1: meta.selector(),
            flag2: meta.selector(),
            flag3: meta.selector(),
            flag4: meta.selector(),
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
    pub ch: UnChangedSelectors<REG_COUNT>,
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
            ch: UnChangedSelectors::new(meta),
        }
    }
}
