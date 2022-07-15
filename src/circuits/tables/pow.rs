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
                    table.assign_cell(
                        || format!("value {}", i),
                        self.values,
                        i,
                        || Value::known(F::from(i as u64)),
                    )?;

                    let power = 2u64.pow(i as _) % 2u64.pow(WORD_BITS);
                    table.assign_cell(
                        || format!("power {}", power),
                        self.values,
                        i,
                        || Value::known(F::from(power)),
                    )?;
                }

                table.assign_cell(
                    || format!("value {}", WORD_BITS),
                    self.values,
                    WORD_BITS as _,
                    || Value::known(F::from(WORD_BITS as u64)),
                )?;

                table.assign_cell(
                    || format!("power {}", 0),
                    self.values,
                    WORD_BITS as _,
                    || Value::known(F::zero()),
                )?;
                Ok(())
            },
        )
    }
}

#[derive(Clone, Debug)]
pub struct PowChip<F: FieldExt, const WORD_BITS: u32> {
    config: PowConfig<WORD_BITS>,
    _marker: PhantomData<F>,
}

impl<F: FieldExt, const WORD_BITS: u32> PowChip<F, WORD_BITS> {
    pub fn construct(config: <Self as Chip<F>>::Config) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }
}

impl<F: FieldExt, const WORD_BITS: u32> Chip<F> for PowChip<F, WORD_BITS> {
    type Config = PowConfig<WORD_BITS>;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}
