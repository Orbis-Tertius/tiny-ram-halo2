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
    // Page 34
    pub v_addr: Selector,
}

impl<const REG_COUNT: usize> ExeRow<REG_COUNT> {
    pub fn new<F: FieldExt>(meta: &mut ConstraintSystem<F>) -> ExeRow<REG_COUNT> {
        ExeRow {
            pc: meta.selector(),
            immediate: meta.selector(),
            regs: [0; REG_COUNT].map(|_| meta.selector()),
            v_addr: meta.selector(),
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
pub struct Out<T> {
    /// logical
    pub and: T,
    pub xor: T,
    pub or: T,

    /// arithmetic
    pub sum: T,
    pub prog: T,
    pub ssum: T,
    pub sprod: T,
    pub mod_: T,

    pub shift: T,

    pub flag1: T,
    pub flag2: T,
    pub flag3: T,
    pub flag4: T,
}

impl<T> Out<T> {
    pub fn new(mut new_fn: impl FnMut() -> T) -> Out<T> {
        Out {
            and: new_fn(),
            xor: new_fn(),
            or: new_fn(),
            sum: new_fn(),
            prog: new_fn(),
            ssum: new_fn(),
            sprod: new_fn(),
            mod_: new_fn(),
            shift: new_fn(),
            flag1: new_fn(),
            flag2: new_fn(),
            flag3: new_fn(),
            flag4: new_fn(),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct TempVarSelectors<const REG_COUNT: usize> {
    pub a: SelectionVector<REG_COUNT>,
    pub b: SelectionVector<REG_COUNT>,
    pub c: SelectionVector<REG_COUNT>,
    pub d: SelectionVector<REG_COUNT>,
    pub out: Out<Selector>,
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
            out: Out::new(|| meta.selector()),
            ch: UnChangedSelectors::new(meta),
        }
    }
}
