use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Layouter, Value},
    plonk::{ConstraintSystem, Error, TableColumn},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PowTable<const WORD_BITS: u32> {
    pub values: TableColumn,
    pub powers: TableColumn,
}

impl<const WORD_BITS: u32> PowTable<WORD_BITS> {
    pub fn new<F: FieldExt>(meta: &mut ConstraintSystem<F>) -> Self {
        Self {
            values: meta.lookup_table_column(),
            powers: meta.lookup_table_column(),
        }
    }

    pub fn alloc_table<F: FieldExt>(
        self,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        layouter.assign_table(
            || "Pow table",
            |mut table| {
                for i in 0..(WORD_BITS as usize) {
                    table
                        .assign_cell(
                            || format!("value {}", i),
                            self.values,
                            i,
                            || Value::known(F::from(i as u64)),
                        )
                        .unwrap();

                    let power = 2u64.pow(i as _) % 2u64.pow(WORD_BITS);
                    table
                        .assign_cell(
                            || format!("power {}", power),
                            self.powers,
                            i,
                            || Value::known(F::from(power)),
                        )
                        .unwrap();
                }

                table
                    .assign_cell(
                        || format!("value {}", WORD_BITS),
                        self.values,
                        WORD_BITS as _,
                        || Value::known(F::from(WORD_BITS as u64)),
                    )
                    .unwrap();

                table.assign_cell(
                    || format!("power {}", 0),
                    self.powers,
                    WORD_BITS as _,
                    || Value::known(F::zero()),
                )
            },
        )
    }
}
