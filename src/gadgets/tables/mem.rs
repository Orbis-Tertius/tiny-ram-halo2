use halo2_proofs::plonk::{Advice, Column, Instance};

pub struct MemChip {}

pub struct MemConfig {
    // not sure if this can be and Instance Column.
    address: Column<Instance>,
    initial_value: Column<Advice>,
    usd: Column<Advice>,
}
