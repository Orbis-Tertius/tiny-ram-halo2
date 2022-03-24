use std::marker::PhantomData;

use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Chip, Layouter, Region, SimpleFloorPlanner},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Fixed},
};

use crate::{
    gadgets::and::AndChip,
    trace::{Step, Trace},
};

use super::{
    even_bits::{EvenBitsChip, EvenBitsConfig},
    instructions::Instructions,
};

pub struct ExeChip<F: FieldExt, const WORD_BITS: u32, const REG_COUNT: usize> {
    config: ExeConfig<WORD_BITS, REG_COUNT>,
    _marker: PhantomData<F>,
}

/// The both constant parameters `WORD_BITS`, `REG_COUNT` will always fit in a `u8`.
/// `u32`, and `usize`, were picked for convenience.
#[derive(Debug, Clone, Copy)]
pub struct ExeConfig<const WORD_BITS: u32, const REG_COUNT: usize> {
    // Not sure this is right.
    time: Column<Fixed>,
    pc: Column<Advice>,
    instruction: Instructions<WORD_BITS>,
    immediate: Column<Advice>,
    reg: [Column<Advice>; REG_COUNT],
    a: Column<Advice>,
    b: Column<Advice>,
    c: Column<Advice>,
    d: Column<Advice>,
    // TODO out is much bigger
    // out: Column<Advice>,

    // t_link: Column<Advice>,
    // v_link: Column<Advice>,
    // v_init: Column<Advice>,
    // s: Column<Advice>,
    // l: Column<Advice>,

    // temp_vars: TempVarSelectors<REG_COUNT>,
}

impl<F: FieldExt, const WORD_BITS: u32, const REG_COUNT: usize> Chip<F>
    for ExeChip<F, WORD_BITS, REG_COUNT>
{
    type Config = ExeConfig<WORD_BITS, REG_COUNT>;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

impl<F: FieldExt, const WORD_BITS: u32, const REG_COUNT: usize> ExeChip<F, WORD_BITS, REG_COUNT> {
    fn construct(config: ExeConfig<WORD_BITS, REG_COUNT>) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> ExeConfig<WORD_BITS, REG_COUNT> {
        let time = meta.fixed_column();
        meta.enable_constant(time);

        let pc = meta.advice_column();
        meta.enable_equality(pc);

        let instruction = Instructions::new_configured(meta);

        let immediate = meta.advice_column();

        // We cannot write `[meta.advice_column(); REG_COUNT]`,
        // That would produce an array of the same advice copied REG_COUNT times.
        //
        // See Rust's array initialization semantics.
        let reg = [0; REG_COUNT].map(|_| meta.advice_column());
        for column in &reg {
            meta.enable_equality(*column);
        }

        // Temporary vars
        let a = meta.advice_column();
        let b = meta.advice_column();
        let c = meta.advice_column();
        let d = meta.advice_column();

        ExeConfig {
            time,
            pc,
            instruction,
            immediate,
            reg,
            a,
            b,
            c,
            d,
        }
    }

    fn step(&self, mut layouter: impl Layouter<F>, step: Step<REG_COUNT>) -> Result<(), Error> {
        let config = self.config();

        layouter
            .assign_region(
                || format!("{:?}", step),
                |mut region: Region<'_, F>| {
                    region
                        .assign_fixed(
                            || format!("time: {:?}", step.time),
                            config.time,
                            0,
                            || Ok(F::from_u128(step.time.0 as u128)),
                        )
                        .unwrap();

                    region
                        .assign_advice(
                            || format!("pc: {:?}", step.pc),
                            config.pc,
                            0,
                            || Ok(F::from_u128(step.pc.0 as u128)),
                        )
                        .unwrap();

                    config
                        .instruction
                        .syn(config.immediate, &mut region, step.instruction);

                    Ok(())
                },
            )
            .unwrap();
        Ok(())
    }
}

#[derive(Default)]
pub struct ExeCircuit<const WORD_BITS: u32, const REG_COUNT: usize> {
    pub b: Option<Trace<WORD_BITS, REG_COUNT>>,
}

impl<F: FieldExt, const WORD_BITS: u32, const REG_COUNT: usize> Circuit<F>
    for ExeCircuit<WORD_BITS, REG_COUNT>
{
    type Config = (ExeConfig<WORD_BITS, REG_COUNT>, EvenBitsConfig);
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        // We create the two advice columns that AndChip uses for I/O.
        let advice = [meta.advice_column(), meta.advice_column()];

        (
            ExeChip::<F, WORD_BITS, REG_COUNT>::configure(meta),
            EvenBitsChip::<F, WORD_BITS>::configure(meta, advice),
        )
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let and_chip = AndChip::<F, WORD_BITS>::construct(config.0.instruction.and.1);
        let even_bits_chip = EvenBitsChip::<F, WORD_BITS>::construct(config.1);
        even_bits_chip.alloc_table(&mut layouter.namespace(|| "alloc table"))?;

        todo!()
    }
}

#[test]
fn load_and_answer() {}
