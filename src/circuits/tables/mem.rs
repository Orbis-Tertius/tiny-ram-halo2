use std::marker::PhantomData;

use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Chip, Layouter, Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Constraints, Error, Expression},
    poly::Rotation,
};

use crate::trace::{Access, Mem};

use super::{
    even_bits::{EvenBitsConfig, EvenBitsTable},
    TableSelector,
};

pub struct MemChip<const WORD_BITS: u32, F: FieldExt> {
    config: MemConfig<WORD_BITS>,
    _marker: PhantomData<F>,
}

#[derive(Debug, Clone, Copy)]
pub struct MemConfig<const WORD_BITS: u32> {
    extent: TableSelector,
    address: Column<Advice>,
    time: Column<Advice>,

    init: Column<Advice>,
    store: Column<Advice>,
    load: Column<Advice>,

    // The most recently stored value.
    value: Column<Advice>,

    /// Defined as `min(address_next - address - 1, 0)`;
    /// The evenbits decomposition enforces that the difference is positive.
    address_increment: EvenBitsConfig<WORD_BITS>,
    /// The difference between time and time on the next row.
    time_increment: EvenBitsConfig<WORD_BITS>,
}

impl<const WORD_BITS: u32, F: FieldExt> Chip<F> for MemChip<WORD_BITS, F> {
    type Config = MemConfig<WORD_BITS>;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

impl<const WORD_BITS: u32, F: FieldExt> MemChip<WORD_BITS, F> {
    /// Currently this is the same as `ExeConfig::TABLE_LEN`.
    /// Programs will usually be much smaller than traces,
    /// so we should reduce this to allow stacking.
    const TABLE_LEN: usize = 2usize.pow(WORD_BITS / 2);

    pub fn construct(config: MemConfig<WORD_BITS>) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        even_bits: EvenBitsTable<WORD_BITS>,
    ) -> MemConfig<WORD_BITS> {
        let extent = TableSelector::configure(meta);

        let address = meta.advice_column();
        let time = meta.advice_column();
        let init = meta.advice_column();
        let store = meta.advice_column();
        let load = meta.advice_column();

        let value = meta.advice_column();

        let address_increment = meta.advice_column();
        let address_increment = EvenBitsConfig::configure(
            meta,
            address_increment,
            &[extent.s_trace],
            extent.s_table,
            even_bits,
        );

        let time_increment = meta.advice_column();
        let time_increment = EvenBitsConfig::configure(
            meta,
            time_increment,
            &[extent.s_trace],
            extent.s_table,
            even_bits,
        );

        meta.create_gate("Mem", |meta| {
            let one = Expression::Constant(F::one());

            // We query s_trace next since all our constraints are on the current and next row.
            // The last line of the trace is constrained by the prior line.
            let s_trace_next = extent.query_trace_next(meta);

            let address_next = meta.query_advice(address, Rotation::next());
            let address = meta.query_advice(address, Rotation::cur());

            let address_increment =
                meta.query_advice(address_increment.word, Rotation::cur());

            let time_next = meta.query_advice(time, Rotation::next());
            let time = meta.query_advice(time, Rotation::cur());

            let time_increment =
                meta.query_advice(time_increment.word, Rotation::cur());

            let same_cycle = address_next.clone() - address.clone();
            let end_cycle = address_next - address - one.clone() - address_increment;

            let time_sorted = time_next - time - time_increment;

            let init_next = meta.query_advice(init, Rotation::next());

            // The table is sorted by address and then time.
            // `init = 0` or store can be the start of a access trace over an address.
            Constraints::with_selector(
                s_trace_next,
                [
                    // The next row may belong to a different access trace on a larger address.
                    end_cycle.clone() * same_cycle,
                    // The next row may occur at a latter time if it's in a different access trace.
                    end_cycle.clone() * time_sorted,
                    // The next row may be a initial value from the tape
                    // if it's the start of an access trace.
                    end_cycle * (init_next - one),
                ],
            )
        });

        MemConfig {
            extent,
            address,
            time,
            init,
            store,
            load,
            value,
            address_increment,
            time_increment,
        }
    }

    pub fn assign_mem(
        &self,
        mut layouter: impl Layouter<F>,
        mem: Mem<WORD_BITS>,
    ) -> Result<(), Error> {
        let config = self.config();

        layouter.assign_region(
            || "Mem",
            |mut region: Region<'_, F>| {
                config
                    .extent
                    .alloc_table_rows(&mut region, Self::TABLE_LEN)?;

                let mut prior_address = 0;
                let mut offset = 0;

                for (address_val, accesses) in mem.address.iter() {
                    // TODO don't generate init for sequences init, store..
                    let mut recent_stored_value: u64 =
                        accesses.initial_value().unwrap().0.into();
                    let mut prior_time = 0;

                    for access in accesses.0.iter() {
                        if let Access::Store { value, .. } = access {
                            recent_stored_value = value.0.into();
                        }

                        let MemConfig {
                            extent,
                            address,
                            time: _,
                            init,
                            store,
                            load,
                            value,
                            address_increment,
                            time_increment: _,
                        } = *config;

                        extent.enable_row_of_table(&mut region, offset, true)?;

                        let time_val: u64 =
                            access.time().map(|a| a.0).unwrap_or(0).into();

                        self.assign_time(&mut region, offset, prior_time, time_val)?;
                        prior_time = time_val;

                        region.assign_advice(
                            || format!("address: {}", address_val.0),
                            address,
                            offset,
                            || Value::known(F::from(u64::from(address_val.0))),
                        )?;

                        let address_increment_val =
                            (address_val.0 - prior_address).saturating_sub(1);
                        let address_increment_val_f =
                            F::from(u64::from(address_increment_val));
                        region.assign_advice(
                            || {
                                format!(
                                    "address_increment: {}",
                                    address_increment_val
                                )
                            },
                            address_increment.word,
                            offset,
                            || Value::known(address_increment_val_f),
                        )?;
                        address_increment.assign_decompose(
                            &mut region,
                            address_increment_val_f,
                            offset,
                        );

                        let is_load = access.is_load();
                        region.assign_advice(
                            || format!("load: {}", is_load),
                            load,
                            offset,
                            || Value::known(F::from(is_load)),
                        )?;

                        let is_store = access.is_store();
                        region.assign_advice(
                            || format!("store: {}", is_store),
                            store,
                            offset,
                            || Value::known(F::from(is_store)),
                        )?;

                        let is_init = access.is_init();
                        region.assign_advice(
                            || format!("init: {}", is_init),
                            init,
                            offset,
                            || Value::known(F::from(is_init)),
                        )?;

                        region.assign_advice(
                            || format!("value: {}", recent_stored_value),
                            value,
                            offset,
                            || Value::known(F::from(recent_stored_value)),
                        )?;

                        offset += 1;
                    }
                    prior_address = address_val.0;
                }

                Ok(())
            },
        )
    }

    pub fn assign_time(
        &self,
        region: &mut Region<F>,
        offset: usize,
        prior_time: u64,
        time_val: u64,
    ) -> Result<(), Error> {
        region.assign_advice(
            || format!("time: {}", time_val),
            self.config.time,
            offset,
            || Value::known(F::from(time_val)),
        )?;

        let time_increment_val = (time_val - prior_time).saturating_sub(1);
        let time_increment_val_f = F::from(time_increment_val);
        region.assign_advice(
            || format!("time_increment: {}", time_increment_val),
            self.config.time_increment.word,
            offset,
            || Value::known(time_increment_val_f),
        )?;
        self.config.time_increment.assign_decompose(
            region,
            time_increment_val_f,
            offset,
        );

        Ok(())
    }
}
