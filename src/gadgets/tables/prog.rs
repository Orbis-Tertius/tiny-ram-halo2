use std::marker::PhantomData;

use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Chip, Layouter, Region, SimpleFloorPlanner},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Selector},
};

use crate::trace;

use super::{
    aux::{SelectionVector, TempVarSelectors},
    even_bits::{EvenBitsChip, EvenBitsConfig},
    instructions::Instructions,
};

pub struct ProgChip<F: FieldExt, const WORD_BITS: u32, const REG_COUNT: usize> {
    config: ProgConfig<WORD_BITS, REG_COUNT>,
    _marker: PhantomData<F>,
}

#[derive(Debug, Clone, Copy)]
pub struct ProgConfig<const WORD_BITS: u32, const REG_COUNT: usize> {
    pc: Column<Advice>,
    /// It is unclear what the correct represention of a instruction is.
    /// Exe_inst_t and Prog_inst_pc may even have diffrent representions.
    instruction: Instructions<WORD_BITS, REG_COUNT>,
    immediate: Column<Advice>,

    s: Selector,
    l: Selector,

    temp_vars: TempVarSelectors<REG_COUNT>,
}

impl<F: FieldExt, const WORD_BITS: u32, const REG_COUNT: usize> Chip<F>
    for ProgChip<F, WORD_BITS, REG_COUNT>
{
    type Config = ProgConfig<WORD_BITS, REG_COUNT>;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

impl<F: FieldExt, const WORD_BITS: u32, const REG_COUNT: usize>
    ProgChip<F, WORD_BITS, REG_COUNT>
{
    fn construct(config: ProgConfig<WORD_BITS, REG_COUNT>) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }

    fn configure(
        meta: &mut ConstraintSystem<F>,
    ) -> ProgConfig<WORD_BITS, REG_COUNT> {
        let pc = meta.advice_column();
        meta.enable_equality(pc);

        let instruction = Instructions::new_configured(meta);
        let immediate = meta.advice_column();

        let s = meta.selector();
        let l = meta.selector();

        let temp_vars = TempVarSelectors::new(meta);
        ProgConfig {
            pc,
            instruction,
            immediate,
            s,
            l,
            temp_vars,
        }
    }

    fn program(
        &self,
        mut layouter: impl Layouter<F>,
        program: &trace::Program,
    ) -> Result<(), Error> {
        let config = self.config;
        for (pc, inst) in program.0.iter().enumerate() {
            layouter
                .assign_region(
                    || format!("{}", inst),
                    |mut region: Region<'_, F>| {
                        region
                            .assign_advice(
                                || format!("pc: {}", pc),
                                config.pc,
                                0,
                                || Ok(F::from_u128(pc as u128)),
                            )
                            .unwrap();

                        config.instruction.syn(
                            config.immediate,
                            config.temp_vars,
                            &mut region,
                            *inst,
                        );

                        Ok(())
                    },
                )
                .unwrap();
        }
        Ok(())
    }
}

#[derive(Default)]
pub struct ProgCircuit<const WORD_BITS: u32, const REG_COUNT: usize> {
    pub prog: Option<trace::Program>,
}

impl<F: FieldExt, const WORD_BITS: u32, const REG_COUNT: usize> Circuit<F>
    for ProgCircuit<WORD_BITS, REG_COUNT>
{
    type Config = (ProgConfig<WORD_BITS, REG_COUNT>, EvenBitsConfig);
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        // We create the two advice columns that AndChip uses for I/O.
        let advice = [meta.advice_column(), meta.advice_column()];

        (
            ProgChip::<F, WORD_BITS, REG_COUNT>::configure(meta),
            EvenBitsChip::<F, WORD_BITS>::configure(meta, advice),
        )
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let even_bits_chip = EvenBitsChip::<F, WORD_BITS>::construct(config.1);
        even_bits_chip.alloc_table(&mut layouter.namespace(|| "alloc table"))?;
        let prog_chip = ProgChip::<F, WORD_BITS, REG_COUNT>::construct(config.0);

        let prog = self
            .prog
            .as_ref()
            .expect("A trace must be set before synthesis");
        for inst in prog.0.iter() {
            prog_chip
                .program(layouter.namespace(|| format!("{}", inst)), prog)
                .unwrap();
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use halo2_proofs::dev::MockProver;
    use pasta_curves::Fp;

    use crate::{gadgets::tables::prog::ProgCircuit, trace::*};

    fn load_and_answer<const WORD_BITS: u32, const REG_COUNT: usize>(
    ) -> Trace<WORD_BITS, REG_COUNT> {
        let prog = Program(vec![
            Instruction::LoadW(LoadW {
                ri: RegName(0),
                a: ImmediateOrRegName::Immediate(Word(0)),
            }),
            Instruction::And(And {
                ri: RegName(1),
                rj: RegName(0),
                a: ImmediateOrRegName::Immediate(Word(0b1)),
            }),
            Instruction::Answer(Answer {
                a: ImmediateOrRegName::RegName(RegName(1)),
            }),
        ]);

        let trace = prog.eval::<WORD_BITS, REG_COUNT>(Mem::new(&[Word(0b1)], &[]));
        assert_eq!(trace.ans.0, 0b1);
        trace
    }

    #[test]
    fn circuit_layout_test() {
        const WORD_BITS: u32 = 8;
        const REG_COUNT: usize = 8;
        let prog = Some(load_and_answer::<WORD_BITS, REG_COUNT>().prog);

        let k = 1 + WORD_BITS / 2;

        // Instantiate the circuit with the private inputs.
        let circuit = ProgCircuit::<WORD_BITS, REG_COUNT> { prog };
        use plotters::prelude::*;
        let root =
            BitMapBackend::new("layout.png", (15360, 7680)).into_drawing_area();
        root.fill(&WHITE).unwrap();
        let root = root
            .titled("Prog Circuit Layout", ("sans-serif", 60))
            .unwrap();

        halo2_proofs::dev::CircuitLayout::default()
            .mark_equality_cells(true)
            .show_equality_constraints(true)
            // The first argument is the size parameter for the circuit.
            .render::<Fp, _, _>(k, &circuit, &root)
            .unwrap();

        let dot_string = halo2_proofs::dev::circuit_dot_graph::<Fp, _>(&circuit);
        let mut dot_graph = std::fs::File::create("circuit.dot").unwrap();
        std::io::Write::write_all(&mut dot_graph, dot_string.as_bytes()).unwrap();
    }

    fn mock_prover_test<const WORD_BITS: u32, const REG_COUNT: usize>(
        trace: Trace<WORD_BITS, REG_COUNT>,
    ) {
        let k = 1 + WORD_BITS / 2;
        let circuit = ProgCircuit::<WORD_BITS, REG_COUNT> {
            prog: Some(trace.prog),
        };

        // Given the correct public input, our circuit will verify.
        let prover = MockProver::<Fp>::run(k, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn load_and_answer_mock_prover() {
        mock_prover_test::<8, 8>(load_and_answer())
    }

    #[test]
    fn answer_mock_prover() {
        let prog = Program(vec![Instruction::Answer(Answer {
            a: ImmediateOrRegName::Immediate(Word(1)),
        })]);

        let trace = prog.eval::<8, 8>(Mem::new(&[], &[]));
        assert_eq!(trace.ans.0, 1);

        mock_prover_test::<8, 8>(trace)
    }
}
