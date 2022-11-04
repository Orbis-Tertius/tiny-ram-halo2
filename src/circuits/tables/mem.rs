use std::marker::PhantomData;

use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Chip, Layouter, Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Constraints, Expression, Selector},
    poly::Rotation,
};

use crate::trace::{Access, Mem};

use super::even_bits::{EvenBitsConfig, EvenBitsTable};

pub struct MemChip<const WORD_BITS: u32, F: FieldExt> {
    config: MemConfig<WORD_BITS>,
    _marker: PhantomData<F>,
}

#[derive(Debug, Clone, Copy)]
pub struct MemConfig<const WORD_BITS: u32> {
    s_mem_table: Selector,
    address: Column<Advice>,
    time: Column<Advice>,

    init: Column<Advice>,
    store: Column<Advice>,
    load: Column<Advice>,

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
    fn construct(config: MemConfig<WORD_BITS>) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }

    fn configure(
        meta: &mut ConstraintSystem<F>,
        even_bits: EvenBitsTable<WORD_BITS>,
    ) -> MemConfig<WORD_BITS> {
        let s_mem_table = meta.selector();

        let address = meta.advice_column();
        let time = meta.advice_column();
        let used = meta.advice_column();
        let store = meta.advice_column();
        let load = meta.advice_column();

        let address_increment = meta.advice_column();
        let address_increment = EvenBitsConfig::configure(
            meta,
            address_increment,
            &[],
            s_mem_table,
            even_bits,
        );

        let time_increment = meta.advice_column();
        let time_increment = EvenBitsConfig::configure(
            meta,
            time_increment,
            &[],
            s_mem_table,
            even_bits,
        );

        meta.create_gate("Mem", |meta| {
            let one = Expression::Constant(F::one());

            let s_mem_table = meta.query_selector(s_mem_table);

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

            let usd_next = meta.query_advice(used, Rotation::next());

            // The table is sorted by address and then time.
            // `usd = 0` or store can be the start of a access trace over an address.
            Constraints::with_selector(
                s_mem_table,
                [
                    // The next row may belong to a different access trace on a larger address.
                    end_cycle.clone() * same_cycle,
                    // The next row may occur at a latter time if it's in a different access trace.
                    end_cycle.clone() * time_sorted,
                    // The next row may be a initial value from the tape
                    // if it's the start of an access trace.
                    end_cycle * (usd_next - one),
                ],
            )
        });

        MemConfig {
            s_mem_table,
            address,
            time,
            init: used,
            store,
            load,
            address_increment,
            time_increment,
        }
    }

    fn accesses(&self, mut layouter: impl Layouter<F>, mem: Mem<WORD_BITS>) {
        let config = self.config();

        let mut prior_address = 0;

        for (address_val, accesses) in mem.address.iter() {
            // TODO don't generate init for sequences init, store..
            let mut recent_stored_value = accesses.initial_value().unwrap();

            accesses
                .0
                .iter()
                .enumerate()
                .fold(0, |prior_time, (offset, access)| {
                    if let Access::Store { value, .. } = access {
                        recent_stored_value = *value;
                    }

                    layouter
                        .assign_region(
                            || "Mem",
                            |mut region: Region<'_, F>| {
                                let MemConfig {
                                    s_mem_table: _,
                                    address,
                                    time,
                                    init,
                                    store,
                                    load,
                                    address_increment,
                                    time_increment,
                                } = *config;

                                let time_val =
                                    access.time().map(|a| a.0).unwrap_or(0);
                                region.assign_advice(
                                    || format!("time: {}", time_val),
                                    time,
                                    offset,
                                    || Value::known(F::from(u64::from(time_val))),
                                )?;

                                region.assign_advice(
                                    || format!("address: {}", address_val.0),
                                    address,
                                    offset,
                                    || {
                                        Value::known(F::from(u64::from(
                                            address_val.0,
                                        )))
                                    },
                                )?;

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

                                let address_increment_val = (address_val.0
                                    - prior_address)
                                    .saturating_sub(1);
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

                                let time_increment_val =
                                    (time_val - prior_time).saturating_sub(1);
                                let time_increment_val_f =
                                    F::from(u64::from(time_increment_val));
                                region.assign_advice(
                                    || {
                                        format!(
                                            "time_increment: {}",
                                            time_increment_val
                                        )
                                    },
                                    time_increment.word,
                                    offset,
                                    || Value::known(time_increment_val_f),
                                )?;
                                time_increment.assign_decompose(
                                    &mut region,
                                    time_increment_val_f,
                                    offset,
                                );

                                Ok(())
                            },
                        )
                        .unwrap();

                    access.time().map(|a| a.0).unwrap_or(0)
                });
            prior_address = address_val.0;
        }
    }
}
