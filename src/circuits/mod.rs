use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner},
    plonk::{Circuit, ConstraintSystem, Error},
};

use crate::trace::Trace;

use self::tables::{
    exe::{ExeChip, ExeConfig},
    prog::ProgConfig,
};

pub mod changed;
pub mod flag1;
pub mod flag2;
pub mod flag3;
pub mod flag4;
pub mod logic;
pub mod modulo;
pub mod prod;
pub mod shift;
pub mod sprod;
pub mod ssum;
pub mod sum;
pub mod tables;

#[derive(Default, Debug, Clone)]
pub struct TinyRamCircuit<const WORD_BITS: u32, const REG_COUNT: usize> {
    pub trace: Option<Trace<WORD_BITS, REG_COUNT>>,
}

impl<
        F: halo2_proofs::arithmetic::FieldExt,
        const WORD_BITS: u32,
        const REG_COUNT: usize,
    > Circuit<F> for TinyRamCircuit<WORD_BITS, REG_COUNT>
{
    type Config = (
        ProgConfig<WORD_BITS, REG_COUNT>,
        ExeConfig<WORD_BITS, REG_COUNT>,
    );
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let prog_config = ProgConfig::configure(meta);
        let exe_config = ExeChip::<F, WORD_BITS, REG_COUNT>::configure(meta);

        prog_config.lookup(
            meta,
            exe_config.extent.s_trace,
            exe_config.pc,
            exe_config.program_line,
        );

        (prog_config, exe_config)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let exe_chip =
            ExeChip::<F, WORD_BITS, REG_COUNT>::construct(&mut layouter, config.1);
        config.0.assign_prog(&mut layouter)?;

        if let Some(trace) = &self.trace {
            exe_chip.assign_trace(layouter.namespace(|| "Trace"), trace)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use halo2_proofs::dev::MockProver;
    use halo2_proofs::pasta::Fp;
    use proptest::{prop_compose, proptest};

    use crate::{
        circuits::tables::exe::ExeCircuit, instructions::*,
        test_utils::gen_proofs_and_verify, trace::*,
    };

    fn load_and_answer<const WORD_BITS: u32, const REG_COUNT: usize>(
        a: u32,
        b: u32,
    ) -> Trace<WORD_BITS, REG_COUNT> {
        let prog = Program(vec![
            Instruction::LoadW(LoadW {
                ri: RegName(0),
                a: ImmediateOrRegName::Immediate(Word(b)),
            }),
            Instruction::And(And {
                ri: RegName(1),
                rj: RegName(0),
                a: ImmediateOrRegName::Immediate(Word(a)),
            }),
            Instruction::Answer(Answer {
                a: ImmediateOrRegName::Immediate(Word(1)),
            }),
        ]);

        let trace = prog.eval::<WORD_BITS, REG_COUNT>(Mem::new(&[Word(0b1)], &[]));
        assert_eq!(trace.ans.0, 1);
        trace
    }
    fn mov_ins_answer<const WORD_BITS: u32, const REG_COUNT: usize>(
        ins: Instruction<RegName, ImmediateOrRegName>,
        b: u32,
    ) -> Trace<WORD_BITS, REG_COUNT> {
        let prog = Program(vec![
            Instruction::Mov(Mov {
                ri: RegName(0),
                a: ImmediateOrRegName::Immediate(Word(b)),
            }),
            ins,
            Instruction::Answer(Answer {
                a: ImmediateOrRegName::Immediate(Word(1)),
            }),
        ]);

        let trace = prog.eval::<WORD_BITS, REG_COUNT>(Mem::new(&[Word(0b1)], &[]));
        assert_eq!(trace.ans.0, 1);
        trace
    }

    fn mov_and_answer<const WORD_BITS: u32, const REG_COUNT: usize>(
        a: u32,
        b: u32,
    ) -> Trace<WORD_BITS, REG_COUNT> {
        mov_ins_answer(
            Instruction::And(And {
                ri: RegName(1),
                rj: RegName(0),
                a: ImmediateOrRegName::Immediate(Word(a)),
            }),
            b,
        )
    }

    fn mov_xor_answer<const WORD_BITS: u32, const REG_COUNT: usize>(
        a: u32,
        b: u32,
    ) -> Trace<WORD_BITS, REG_COUNT> {
        mov_ins_answer(
            Instruction::Xor(Xor {
                ri: RegName(1),
                rj: RegName(0),
                a: ImmediateOrRegName::Immediate(Word(a)),
            }),
            b,
        )
    }

    fn mov_or_answer<const WORD_BITS: u32, const REG_COUNT: usize>(
        a: u32,
        b: u32,
    ) -> Trace<WORD_BITS, REG_COUNT> {
        mov_ins_answer(
            Instruction::Or(Or {
                ri: RegName(1),
                rj: RegName(0),
                a: ImmediateOrRegName::Immediate(Word(a)),
            }),
            b,
        )
    }

    fn mov_add_answer<const WORD_BITS: u32, const REG_COUNT: usize>(
        a: u32,
        b: u32,
    ) -> Trace<WORD_BITS, REG_COUNT> {
        mov_ins_answer(
            Instruction::Add(Add {
                ri: RegName(1),
                rj: RegName(0),
                a: ImmediateOrRegName::Immediate(Word(a)),
            }),
            b,
        )
    }

    fn mov_sub_answer<const WORD_BITS: u32, const REG_COUNT: usize>(
        a: u32,
        b: u32,
    ) -> Trace<WORD_BITS, REG_COUNT> {
        mov_ins_answer(
            Instruction::Sub(Sub {
                ri: RegName(1),
                rj: RegName(0),
                a: ImmediateOrRegName::Immediate(Word(a)),
            }),
            b,
        )
    }

    fn mov_cmpe_answer<const WORD_BITS: u32, const REG_COUNT: usize>(
        a: u32,
        b: u32,
    ) -> Trace<WORD_BITS, REG_COUNT> {
        mov_ins_answer(
            Instruction::Cmpe(Cmpe {
                ri: RegName(0),
                a: ImmediateOrRegName::Immediate(Word(a)),
            }),
            b,
        )
    }

    fn mov_cmpa_answer<const WORD_BITS: u32, const REG_COUNT: usize>(
        a: u32,
        b: u32,
    ) -> Trace<WORD_BITS, REG_COUNT> {
        mov_ins_answer(
            Instruction::Cmpa(Cmpa {
                ri: RegName(0),
                a: ImmediateOrRegName::Immediate(Word(a)),
            }),
            b,
        )
    }

    fn mov_cmpae_answer<const WORD_BITS: u32, const REG_COUNT: usize>(
        a: u32,
        b: u32,
    ) -> Trace<WORD_BITS, REG_COUNT> {
        mov_ins_answer(
            Instruction::Cmpae(Cmpae {
                ri: RegName(0),
                a: ImmediateOrRegName::Immediate(Word(a)),
            }),
            b,
        )
    }

    fn mov_cmpg_answer<const WORD_BITS: u32, const REG_COUNT: usize>(
        a: Word,
        b: Word,
    ) -> Trace<WORD_BITS, REG_COUNT> {
        mov_ins_answer(
            Instruction::Cmpg(Cmpg {
                ri: RegName(0),
                a: ImmediateOrRegName::Immediate(a),
            }),
            b.0,
        )
    }

    fn mov_cmpge_answer<const WORD_BITS: u32, const REG_COUNT: usize>(
        a: Word,
        b: Word,
    ) -> Trace<WORD_BITS, REG_COUNT> {
        mov_ins_answer(
            Instruction::Cmpge(Cmpge {
                ri: RegName(0),
                a: ImmediateOrRegName::Immediate(a),
            }),
            b.0,
        )
    }

    fn mov_mull_answer<const WORD_BITS: u32, const REG_COUNT: usize>(
        a: Word,
        b: Word,
    ) -> Trace<WORD_BITS, REG_COUNT> {
        mov_ins_answer(
            Instruction::Mull(Mull {
                ri: RegName(1),
                rj: RegName(0),
                a: ImmediateOrRegName::Immediate(a),
            }),
            b.0,
        )
    }

    fn mov_umulh_answer<const WORD_BITS: u32, const REG_COUNT: usize>(
        a: Word,
        b: Word,
    ) -> Trace<WORD_BITS, REG_COUNT> {
        mov_ins_answer(
            Instruction::Mull(Mull {
                ri: RegName(1),
                rj: RegName(0),
                a: ImmediateOrRegName::Immediate(a),
            }),
            b.0,
        )
    }

    fn mov_smullh_answer<const WORD_BITS: u32, const REG_COUNT: usize>(
        a: Word,
        b: Word,
    ) -> Trace<WORD_BITS, REG_COUNT> {
        mov_ins_answer(
            Instruction::SMulh(SMulh {
                ri: RegName(1),
                rj: RegName(0),
                a: ImmediateOrRegName::Immediate(a),
            }),
            b.0,
        )
    }

    fn mov_umod_answer<const WORD_BITS: u32, const REG_COUNT: usize>(
        a: Word,
        b: Word,
    ) -> Trace<WORD_BITS, REG_COUNT> {
        mov_ins_answer(
            Instruction::UMod(UMod {
                ri: RegName(1),
                rj: RegName(0),
                a: ImmediateOrRegName::Immediate(a),
            }),
            b.0,
        )
    }

    fn mov_udiv_answer<const WORD_BITS: u32, const REG_COUNT: usize>(
        a: Word,
        b: Word,
    ) -> Trace<WORD_BITS, REG_COUNT> {
        mov_ins_answer(
            Instruction::UDiv(UDiv {
                ri: RegName(1),
                rj: RegName(0),
                a: ImmediateOrRegName::Immediate(a),
            }),
            b.0,
        )
    }

    fn mov_shr_answer<const WORD_BITS: u32, const REG_COUNT: usize>(
        a: Word,
        b: Word,
    ) -> Trace<WORD_BITS, REG_COUNT> {
        mov_ins_answer(
            Instruction::Shr(Shr {
                ri: RegName(1),
                rj: RegName(0),
                a: ImmediateOrRegName::Immediate(a),
            }),
            b.0,
        )
    }

    fn mov_shl_answer<const WORD_BITS: u32, const REG_COUNT: usize>(
        a: Word,
        b: Word,
    ) -> Trace<WORD_BITS, REG_COUNT> {
        mov_ins_answer(
            Instruction::Shl(Shl {
                ri: RegName(1),
                rj: RegName(0),
                a: ImmediateOrRegName::Immediate(a),
            }),
            b.0,
        )
    }

    // #[test]
    // fn circuit_layout_test() {
    //     const WORD_BITS: u32 = 8;
    //     const REG_COUNT: usize = 8;
    //     let trace = Some(load_and_answer());

    //     let k = 1 + WORD_BITS / 2;

    //     // Instantiate the circuit with the private inputs.
    //     let circuit = ExeCircuit::<WORD_BITS, REG_COUNT> { trace };
    //     use plotters::prelude::*;
    //     let root =
    //         BitMapBackend::new("layout.png", (1920, 1080)).into_drawing_area();
    //     root.fill(&WHITE).unwrap();
    //     let root = root
    //         .titled("Exe Circuit Layout", ("sans-serif", 60))
    //         .unwrap();

    //     halo2_proofs::dev::CircuitLayout::default()
    //         .mark_equality_cells(true)
    //         .show_equality_constraints(true)
    //         // The first argument is the size parameter for the circuit.
    //         .render::<Fp, _, _>(k, &circuit, &root)
    //         .unwrap();

    //     let dot_string = halo2_proofs::dev::circuit_dot_graph::<Fp, _>(&circuit);
    //     let mut dot_graph = std::fs::File::create("circuit.dot").unwrap();
    //     std::io::Write::write_all(&mut dot_graph, dot_string.as_bytes()).unwrap();
    // }

    fn mock_prover_test<const WORD_BITS: u32, const REG_COUNT: usize>(
        trace: Trace<WORD_BITS, REG_COUNT>,
    ) {
        let k = 2 + WORD_BITS / 2;
        let circuit = ExeCircuit::<WORD_BITS, REG_COUNT> { trace: Some(trace) };

        // Given the correct public input, our circuit will verify.
        let prover = MockProver::<Fp>::run(k, &circuit, vec![]).unwrap();
        prover.assert_satisfied();
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

        let l_and_ans = load_and_answer::<8, 8>(1, 2);
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

    prop_compose! {
      fn signed_word(word_bits: u32)
         (a in -(2i32.pow(word_bits - 1))..2i32.pow(word_bits - 1) - 1)
      -> Word {
          Word::try_from_signed(a, word_bits).unwrap()
      }
    }

    proptest! {
        #[test]
        fn load_and_answer_mock_prover(a in 0..2u32.pow(8), b in 0..2u32.pow(8)) {
            mock_prover_test::<8, 8>(load_and_answer(a, b))
        }

        #[test]
        fn mov_and_answer_mock_prover(a in 0..2u32.pow(8), b in 0..2u32.pow(8)) {
            mock_prover_test::<8, 8>(mov_and_answer(a, b))
        }

        #[test]
        fn mov_xor_answer_mock_prover(a in 0..2u32.pow(8), b in 0..2u32.pow(8)) {
            mock_prover_test::<8, 8>(mov_xor_answer(a, b))
        }

        #[test]
        fn mov_or_answer_mock_prover(a in 0..2u32.pow(8), b in 0..2u32.pow(8)) {
            mock_prover_test::<8, 8>(mov_or_answer(a, b))
        }

        #[test]
        fn mov_add_answer_mock_prover(a in 0..2u32.pow(8), b in 0..2u32.pow(8)) {
            mock_prover_test::<8, 8>(mov_add_answer(a, b))
        }

        #[test]
        fn mov_sub_answer_mock_prover(a in 0..2u32.pow(8), b in 0..2u32.pow(8)) {
            mock_prover_test::<8, 8>(mov_sub_answer(a, b))
        }

        #[test]
        fn mov_mull_answer_mock_prover(a in signed_word(8), b in signed_word(8)) {
            mock_prover_test::<8, 8>(mov_mull_answer(a, b))
        }

        #[test]
        fn mov_umulh_answer_mock_prover(a in signed_word(8), b in signed_word(8)) {
            mock_prover_test::<8, 8>(mov_umulh_answer(a, b))
        }

        #[test]
        fn mov_umod_answer_mock_prover(a in signed_word(8), b in signed_word(8)) {
            mock_prover_test::<8, 8>(mov_umod_answer(a, b))
        }

        #[test]
        fn mov_udiv_answer_mock_prover(a in signed_word(8), b in signed_word(8)) {
            mock_prover_test::<8, 8>(mov_udiv_answer(a, b))
        }

        #[test]
        fn mov_cmpe_answer_mock_prover(a in 0..2u32.pow(8), b in 0..2u32.pow(8)) {
            mock_prover_test::<8, 8>(mov_cmpe_answer(a, b))
        }

        #[test]
        fn mov_cmpa_answer_mock_prover(a in 0..2u32.pow(8), b in 0..2u32.pow(8)) {
            mock_prover_test::<8, 8>(mov_cmpa_answer(a, b))
        }

        #[test]
        fn mov_cmpae_answer_mock_prover(a in 0..2u32.pow(8), b in 0..2u32.pow(8)) {
            mock_prover_test::<8, 8>(mov_cmpae_answer(a, b))
        }

        #[test]
        fn mov_cmpg_answer_mock_prover(a in signed_word(8), b in signed_word(8)) {
            mock_prover_test::<8, 8>(mov_cmpg_answer(a, b))
        }

        #[test]
        fn mov_cmpge_answer_mock_prover(a in signed_word(8), b in signed_word(8)) {
            mock_prover_test::<8, 8>(mov_cmpge_answer(a, b))
        }

        #[test]
        fn mov_smullh_answer_mock_prover(a in signed_word(8), b in signed_word(8)) {
            mock_prover_test::<8, 8>(mov_smullh_answer(a, b))
        }

        #[test]
        fn mov_shl_answer_mock_prover(a in 0..8u32, b in 0..2u32.pow(8)) {
            mock_prover_test::<8, 8>(mov_shl_answer(Word(a), Word(b)))
        }

        #[test]
        fn mov_shr_answer_mock_prover(a in 0..8u32, b in 0..2u32.pow(8)) {
            mock_prover_test::<8, 8>(mov_shr_answer(Word(a), Word(b)))
        }
    }
}
