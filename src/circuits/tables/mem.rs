use std::marker::PhantomData;

use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Chip, Layouter, Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Selector},
};

use crate::trace::{Access, Mem};

pub struct MemChip<F: FieldExt> {
    config: MemConfig,
    _marker: PhantomData<F>,
}

#[derive(Debug, Clone, Copy)]
pub struct MemConfig {
    address: Column<Advice>,
    initial_value: Column<Advice>,
    // It is unclear if `usd` should be a selector
    usd: Selector,
}

impl<F: FieldExt> Chip<F> for MemChip<F> {
    type Config = MemConfig;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

impl<F: FieldExt> MemChip<F> {
    fn construct(config: MemConfig) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> MemConfig {
        let address = meta.advice_column();
        meta.enable_equality(address);

        let initial_value = meta.advice_column();
        meta.enable_equality(initial_value);

        let usd = meta.selector();

        MemConfig {
            address,
            initial_value,
            usd,
        }
    }

    fn accesses<const WORD_BITS: u32>(
        &self,
        mut layouter: impl Layouter<F>,
        mem: Mem<WORD_BITS>,
    ) {
        let config = self.config();

        for (addr, accesses) in mem.address.iter() {
            let initial_value = accesses.initial_value().unwrap();
            for access in accesses.0.iter() {
                layouter
                    .assign_region(
                        || "",
                        |mut region: Region<'_, F>| {
                            region
                                .assign_advice(
                                    || format!("addr: {}", addr.0),
                                    config.address,
                                    0,
                                    || Value::known(F::from_u128(addr.0 as u128)),
                                )
                                .unwrap();

                            region
                                .assign_advice(
                                    || format!("initial_value: {}", addr.0),
                                    config.address,
                                    0,
                                    || {
                                        Value::known(F::from_u128(
                                            initial_value.0 as u128,
                                        ))
                                    },
                                )
                                .unwrap();

                            match access {
                                Access::Init { .. } => {}
                                Access::Load { .. } | Access::Store { .. } => {
                                    config.usd.enable(&mut region, 0)?;
                                }
                            }

                            Ok(())
                        },
                    )
                    .unwrap();
            }
        }
    }
}
