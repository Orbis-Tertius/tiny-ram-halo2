use std::marker::PhantomData;

use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Chip, Layouter, Region, SimpleFloorPlanner},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Selector},
    poly::Rotation,
};

use crate::{
    circuits::and::AndChip,
    trace::{RegName, Step, Trace},
};

use super::{
    aux::{Out, SelectiorsA, TempVarSelectors, TempVarSelectorsRow},
    even_bits::{EvenBitsChip, EvenBitsConfig},
};

pub struct ExeChip<F: FieldExt, const WORD_BITS: u32, const REG_COUNT: usize> {
    config: ExeConfig<WORD_BITS, REG_COUNT>,
    _marker: PhantomData<F>,
}

/// The both constant parameters `WORD_BITS`, `REG_COUNT` will always fit in a `u8`.
/// `u32`, and `usize`, were picked for convenience.
#[derive(Debug, Clone, Copy)]
pub struct ExeConfig<const WORD_BITS: u32, const REG_COUNT: usize> {
    table_max_len: Selector,
    /// This is redundant with 0 padded `time`.
    /// We need it to make the mock prover happy and not giving CellNotAssigned errors.
    /// https://github.com/zcash/halo2/issues/533#issuecomment-1097371369
    ///
    /// It's set on rows 0..exe_len() - 1
    exe_len: Selector,
    time: Column<Advice>,
    pc: Column<Advice>,
    /// `Exe_inst` in the paper.
    opcode: Column<Advice>,
    immediate: Column<Advice>,
    reg: [Column<Advice>; REG_COUNT],
    flag: Column<Advice>,
    address: Column<Advice>,
    value: Column<Advice>,
    a: Column<Advice>,
    b: Column<Advice>,
    c: Column<Advice>,
    d: Column<Advice>,

    out: Out<Column<Advice>>,

    // t_link: Column<Advice>,
    // v_link: Column<Advice>,
    // v_init: Column<Advice>,
    // s: Column<Advice>,
    // l: Column<Advice>,
    temp_var_selectors: TempVarSelectors<REG_COUNT, Column<Advice>>,
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

impl<F: FieldExt, const WORD_BITS: u32, const REG_COUNT: usize>
    ExeChip<F, WORD_BITS, REG_COUNT>
{
    fn construct(config: ExeConfig<WORD_BITS, REG_COUNT>) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> ExeConfig<WORD_BITS, REG_COUNT> {
        let time = meta.advice_column();

        let pc = meta.advice_column();
        meta.enable_equality(pc);

        let opcode = meta.advice_column();

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

        let flag = meta.advice_column();
        let address = meta.advice_column();
        let value = meta.advice_column();
        let out = Out::new(|| meta.advice_column());
        let temp_var_selectors =
            TempVarSelectors::new::<F, ConstraintSystem<F>>(meta);
        let table_max_len = meta.selector();
        let exe_len = meta.selector();

        let config = ExeConfig {
            time,
            pc,
            opcode,
            immediate,
            reg,
            flag,
            address,
            value,
            a,
            b,
            c,
            d,
            out,
            temp_var_selectors,
            table_max_len,
            exe_len,
        };

        {
            let SelectiorsA {
                pc_next,
                reg,
                reg_next,
                a,
                v_addr,
                non_det,
            } = temp_var_selectors.a;

            meta.create_gate("tv[a][pc_next]", |meta| {
                let sa_pc_next = meta.query_advice(pc_next, Rotation::cur());
                let pc_next = meta.query_advice(config.pc, Rotation::next());
                let t_var_a = meta.query_advice(config.a, Rotation::cur());

                // We disable this gate on the last row of the Exe trace.
                // This is fine since the last row must contain Answer 0.
                // If we did not disable pc_next we would be querying an unassigned cell `pc_next`.
                let time_next = meta.query_advice(config.time, Rotation::next());
                // let table_max_len = meta.query_selector(table_max_len);
                let exe_len = meta.query_selector(exe_len);

                // vec![exe_len * time_next * sa_pc_next * (pc_next - t_var_a)]
                vec![exe_len * F::zero()]
            });
        }
        config
    }

    fn assign_trace(
        &self,
        mut layouter: impl Layouter<F>,
        trace: &Trace<WORD_BITS, REG_COUNT>,
    ) -> Result<(), Error> {
        let ExeConfig {
            time,
            pc,
            opcode,
            immediate,
            reg,
            flag,
            address,
            value,
            a,
            b,
            c,
            d,
            out,
            temp_var_selectors,
            table_max_len,
            exe_len,
        } = self.config;

        layouter
            .assign_region(
                || "Exe",
                |mut region: Region<'_, F>| {
                    for i in 0..trace.exe.len() {
                        table_max_len.enable(&mut region, i)?;
                    }

                    for i in 0..trace.exe.len() - 1 {
                        exe_len.enable(&mut region, i)?;
                    }

                    for (i, step) in trace.exe.iter().enumerate() {
                        region
                            .assign_advice(
                                || format!("time: {}", step.time.0),
                                time,
                                i,
                                || Ok(F::from_u128(step.time.0 as u128)),
                            )
                            .unwrap();

                        region
                            .assign_advice(
                                || format!("pc: {}", step.pc.0),
                                pc,
                                i,
                                || Ok(F::from_u128(step.pc.0 as u128)),
                            )
                            .unwrap();

                        region
                            .assign_advice(
                                || format!("opcode: {}", step.instruction.opcode()),
                                opcode,
                                i,
                                || Ok(F::from_u128(step.instruction.opcode())),
                            )
                            .unwrap();

                        let immediate_v = step
                            .instruction
                            .a()
                            .immediate()
                            .unwrap_or_default()
                            .into();
                        region
                            .assign_advice(
                                || format!("immediate: {}", immediate_v),
                                immediate,
                                i,
                                || Ok(F::from_u128(immediate_v)),
                            )
                            .unwrap();

                        // assign registers
                        for ((i, reg), v) in reg.iter().enumerate().zip(step.regs.0)
                        {
                            region
                                .assign_advice(
                                    || format!("r{}: {}", i, v.0),
                                    *reg,
                                    i,
                                    || Ok(F::from_u128(v.into())),
                                )
                                .unwrap();
                        }

                        region
                            .assign_advice(
                                || format!("flag: {}", step.flag),
                                immediate,
                                i,
                                || Ok(F::from(step.flag)),
                            )
                            .unwrap();

                        // Assign temp vars and temp var selectors
                        {
                            let temp_var_selectors_row =
                                TempVarSelectorsRow::<REG_COUNT>::from(
                                    &step.instruction,
                                );

                            temp_var_selectors.push_cells(
                                &mut (&mut region, i),
                                dbg!(temp_var_selectors_row),
                            );

                            let (ta, tb, tc, td) = temp_var_selectors_row
                                .push_temp_var_vals::<F, WORD_BITS>(&trace.exe, i);

                            region
                                .assign_advice(
                                    || format!("a: {}", ta),
                                    a,
                                    i,
                                    || Ok(F::from_u128(ta as u128)),
                                )
                                .unwrap();
                            region
                                .assign_advice(
                                    || format!("b: {}", tb),
                                    b,
                                    i,
                                    || Ok(F::from_u128(tb as u128)),
                                )
                                .unwrap();
                            region
                                .assign_advice(
                                    || format!("c: {}", tc),
                                    c,
                                    i,
                                    || Ok(F::from_u128(tc as u128)),
                                )
                                .unwrap();
                            region
                                .assign_advice(
                                    || format!("d: {}", td),
                                    d,
                                    i,
                                    || Ok(F::from_u128(td as u128)),
                                )
                                .unwrap();
                        }
                    }

                    region
                        .assign_advice(
                            || format!("Terminating time: {}", 0),
                            time,
                            trace.exe.len(),
                            || Ok(F::zero()),
                        )
                        .unwrap();

                    Ok(())
                },
            )
            .unwrap();
        Ok(())
    }
}

#[derive(Default, Debug, Clone)]
pub struct ExeCircuit<const WORD_BITS: u32, const REG_COUNT: usize> {
    pub trace: Option<Trace<WORD_BITS, REG_COUNT>>,
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
        let even_bits_chip = EvenBitsChip::<F, WORD_BITS>::construct(config.1);
        even_bits_chip.alloc_table(&mut layouter.namespace(|| "alloc table"))?;
        let exe_chip = ExeChip::<F, WORD_BITS, REG_COUNT>::construct(config.0);

        if let Some(trace) = &self.trace {
            exe_chip
                .assign_trace(layouter.namespace(|| "Trace"), trace)
                .unwrap();

            Ok(())
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use halo2_proofs::dev::MockProver;
    use halo2_proofs::pasta::Fp;

    use crate::{
        circuits::tables::exe::ExeCircuit, test_utils::gen_proofs_and_verify,
        trace::*,
    };

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
        let trace = Some(load_and_answer());

        let k = 1 + WORD_BITS / 2;

        // Instantiate the circuit with the private inputs.
        let circuit = ExeCircuit::<WORD_BITS, REG_COUNT> { trace };
        use plotters::prelude::*;
        let root =
            BitMapBackend::new("layout.png", (1920, 1080)).into_drawing_area();
        root.fill(&WHITE).unwrap();
        let root = root
            .titled("Exe Circuit Layout", ("sans-serif", 60))
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
        let circuit = ExeCircuit::<WORD_BITS, REG_COUNT> { trace: Some(trace) };

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

    #[test]
    fn two_programs() {
        let ans = {
            let ans = Program(vec![Instruction::Answer(Answer {
                a: ImmediateOrRegName::Immediate(Word(1)),
            })]);
            let ans = ans.eval::<8, 8>(Mem::new(&[], &[]));
            assert_eq!(ans.ans.0, 1);
            ans
        };

        let l_and_ans = load_and_answer::<8, 8>();
        assert_eq!(l_and_ans.ans.0, 1);

        gen_proofs_and_verify::<8, _>(vec![
            (ExeCircuit { trace: Some(ans) }, vec![]),
            (
                ExeCircuit {
                    trace: Some(l_and_ans),
                },
                vec![],
            ),
        ]);
    }
}
