use halo2_proofs::plonk::{Advice, Column};

use super::aux::{SelectionVector, TempVarSelectors};

pub struct ProgChip {}

pub struct ProgConfig<const REG_COUNT: usize> {
    pc: Column<Advice>,
    instruction: Column<Advice>,
    immediate: Column<Advice>,

    temp_vars: TempVarSelectors<REG_COUNT>,
}
