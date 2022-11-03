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
    used: Column<Advice>,
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

        meta.create_gate("Sorted", |meta| {
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
            let new_sorted_cycle = address_next - address - one - address_increment;

            let time_sorted = time_next - time - time_increment;

            // The table is sorted by address and then time.
            Constraints::with_selector(
                s_mem_table,
                [
                    same_cycle * new_sorted_cycle.clone(),
                    new_sorted_cycle * time_sorted,
                ],
            )
        });

        MemConfig {
            s_mem_table,
            address,
            time,
            used,
            store,
            load,
            address_increment,
            time_increment,
        }
    }

    fn accesses(&self, mut layouter: impl Layouter<F>, mem: Mem<WORD_BITS>) {
        //     let config = self.config();

        //     for (addr, accesses) in mem.address.iter() {
        //         let initial_value = accesses.initial_value().unwrap();
        //         for access in accesses.0.iter() {
        //             layouter
        //                 .assign_region(
        //                     || "",
        //                     |mut region: Region<'_, F>| {
        //                         region
        //                             .assign_advice(
        //                                 || format!("addr: {}", addr.0),
        //                                 config.address,
        //                                 0,
        //                                 || Value::known(F::from_u128(addr.0 as u128)),
        //                             )
        //                             .unwrap();

        //                         region
        //                             .assign_advice(
        //                                 || format!("initial_value: {}", addr.0),
        //                                 config.address,
        //                                 0,
        //                                 || {
        //                                     Value::known(F::from_u128(
        //                                         initial_value.0 as u128,
        //                                     ))
        //                                 },
        //                             )
        //                             .unwrap();

        //                         match access {
        //                             Access::Init { .. } => {}
        //                             Access::Load { .. } | Access::Store { .. } => {
        //                                 config.usd.enable(&mut region, 0)?;
        //                             }
        //                         }

        //                         Ok(())
        //                     },
        //                 )
        //                 .unwrap();
        //         }
        //     }
    }
}
