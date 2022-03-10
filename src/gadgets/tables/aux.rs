use halo2_proofs::plonk::Selector;

#[derive(Debug)]
pub struct SelectionVector<const REG_COUNT: usize> {
    row: ExeRow<REG_COUNT>,
    row_next: ExeRow<REG_COUNT>,
}

#[derive(Debug)]
pub struct ExeRow<const REG_COUNT: usize> {
    pc: Selector,
    immediate: Selector,
    regs: [Selector; REG_COUNT],
}

#[derive(Debug)]
pub struct TempVarSelectors<const REG_COUNT: usize> {
    pub a: SelectionVector<REG_COUNT>,
    pub b: SelectionVector<REG_COUNT>,
    pub c: SelectionVector<REG_COUNT>,
    pub d: SelectionVector<REG_COUNT>,
    pub out: SelectionVector<REG_COUNT>,
    pub ch: SelectionVector<REG_COUNT>,
}
