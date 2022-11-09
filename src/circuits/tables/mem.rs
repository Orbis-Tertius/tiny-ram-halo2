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

#[cfg(test)]
mod mem_tests {
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

    // TODO
    // Add tests should fail tests
}
