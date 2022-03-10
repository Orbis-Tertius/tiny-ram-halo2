use halo2_proofs::plonk::{Advice, Column, Fixed};

use super::aux::TempVarSelectors;

pub struct ExeChip {}

pub struct ExeConfig<const REG_COUNT: usize> {
    // Not sure this is right.
    time: Column<Fixed>,
    pc: Column<Advice>,
    instruction: Column<Advice>,
    immediate: Column<Advice>,
    reg: [Column<Advice>; REG_COUNT],
    a: Column<Advice>,
    b: Column<Advice>,
    c: Column<Advice>,
    d: Column<Advice>,
    out: Column<Advice>,
    temp_vars: TempVarSelectors<REG_COUNT>,
}
