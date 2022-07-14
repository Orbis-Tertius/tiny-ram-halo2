use std::marker::PhantomData;

use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Chip, Layouter, Region, SimpleFloorPlanner, Value},
    plonk::{
        Advice, Circuit, Column, ConstraintSystem, Error, Expression, Selector,
    },
    poly::Rotation,
};

use crate::{
    assign::{NewColumn, TrackColumns},
    circuits::{
        flag1::Flag1Config, flag2::Flag2Config, flag3::Flag3Config,
        logic::LogicConfig, modulo::ModConfig, prod::ProdConfig, sprod::SProdConfig,
        ssum::SSumConfig, sum::SumConfig,
    },
    leak_once,
    trace::{Instruction, RegName, Registers, Trace},
};

use super::{
    aux::{
        SelectiorsA, SelectiorsB, SelectiorsC, SelectiorsD, TempVarSelectors,
        TempVarSelectorsRow,
    },
    even_bits::{EvenBitsConfig, EvenBitsTable},
    signed::SignedConfig,
};

pub struct ExeChip<F: FieldExt, const WORD_BITS: u32, const REG_COUNT: usize> {
    config: ExeConfig<WORD_BITS, REG_COUNT>,
    _marker: PhantomData<F>,
}

/// The both constant parameters `WORD_BITS`, `REG_COUNT` will always fit in a `u8`.
/// `u32`, and `usize`, were picked for convenience.
#[derive(Debug, Clone)]
pub struct ExeConfig<const WORD_BITS: u32, const REG_COUNT: usize> {
    table_max_len: Selector,
    /// This is redundant with 0 padded `time`.
    /// We need it to make the mock prover happy and not giving CellNotAssigned errors.
    /// https://github.com/zcash/halo2/issues/533#issuecomment-1097371369
    ///
    /// It's set on rows 0..exe_len() - 1
    exe_len: Selector,

    /// Instruction count
    time: Column<Advice>,
    /// Program count
    pc: Column<Advice>,
    /// `Exe_inst` in the paper.
    opcode: Column<Advice>,
    immediate: Column<Advice>,

    // State
    reg: Registers<REG_COUNT, Column<Advice>>,
    flag: Column<Advice>,

    // Temporary variables
    a: Column<Advice>,
    b: Column<Advice>,
    c: Column<Advice>,
    d: Column<Advice>,

    temp_var_selectors: TempVarSelectors<REG_COUNT, Column<Advice>>,

    // Auxiliary memory columns
    address: Column<Advice>,
    value: Column<Advice>,

    // t_link: Column<Advice>,
    // v_link: Column<Advice>,
    // v_init: Column<Advice>,
    // s: Column<Advice>,
    // l: Column<Advice>,

    // Auxiliary entries used by mutually exclusive constraints.
    even_bits: EvenBitsTable<WORD_BITS>,
    logic: LogicConfig<WORD_BITS>,
    ssum: SSumConfig<WORD_BITS>,
    sprod: SProdConfig<WORD_BITS>,

    /// An implemention detail, used to default fill columns.
    intermediate: Vec<Column<Advice>>,

    // FLAG1 needs no extra advice.
    // flag1: Flag1Config,
    flag2: Flag2Config<WORD_BITS>,
    flag3: Flag3Config<WORD_BITS>,
    // flag4: Flag4Config,
}

impl<const WORD_BITS: u32, const REG_COUNT: usize> ExeConfig<WORD_BITS, REG_COUNT> {
    fn pc_gate<F: FieldExt>(
        &self,
        meta: &mut ConstraintSystem<F>,
        pc_next: Column<Advice>,
        temp_var: Column<Advice>,
        temp_var_name: &str,
    ) {
        meta.create_gate(leak_once(format!("tv.{}.pc", temp_var_name)), |meta| {
            let sa_pc_next = meta.query_advice(pc_next, Rotation::cur());
            let pc = meta.query_advice(self.pc, Rotation::cur());
            let t_var = meta.query_advice(temp_var, Rotation::cur());

            let table_max_len = meta.query_selector(self.table_max_len);

            vec![table_max_len * sa_pc_next * (pc - t_var)]
        });
    }

    fn pc_gate_plus_one<F: FieldExt>(
        &self,
        meta: &mut ConstraintSystem<F>,
        pc_next: Column<Advice>,
        temp_var: Column<Advice>,
        temp_var_name: &str,
    ) {
        meta.create_gate(leak_once(format!("tv.{}.pc+1", temp_var_name)), |meta| {
            let sa_pc_next = meta.query_advice(pc_next, Rotation::cur());
            let pc = meta.query_advice(self.pc, Rotation::cur());
            let t_var = meta.query_advice(temp_var, Rotation::cur());

            let table_max_len = meta.query_selector(self.table_max_len);

            vec![
                table_max_len
                    * sa_pc_next
                    * ((pc + Expression::Constant(F::one())) - t_var),
            ]
        });
    }

    fn pc_next_gate<F: FieldExt>(
        &self,
        meta: &mut ConstraintSystem<F>,
        pc_next: Column<Advice>,
        temp_var: Column<Advice>,
        temp_var_name: &str,
    ) {
        meta.create_gate(
            leak_once(format!("tv.{}.pc_next", temp_var_name)),
            |meta| {
                let sa_pc_next = meta.query_advice(pc_next, Rotation::cur());
                let pc_next = meta.query_advice(self.pc, Rotation::next());
                let t_var = meta.query_advice(temp_var, Rotation::cur());

                // We disable this gate on the last row of the Exe trace.
                // This is fine since the last row must contain Answer 0.
                // If we did not disable pc_next we would be querying an unassigned cell `pc_next`.
                let time_next = meta.query_advice(self.time, Rotation::next());
                let exe_len = meta.query_selector(self.exe_len);

                vec![exe_len * time_next * sa_pc_next * (pc_next - t_var)]
            },
        );
    }

    fn reg_gate<F: FieldExt>(
        &self,
        meta: &mut ConstraintSystem<F>,
        reg_sel: Registers<REG_COUNT, Column<Advice>>,
        temp_var: Column<Advice>,
        temp_var_name: &str,
    ) {
        for (i, s_reg) in reg_sel.0.into_iter().enumerate() {
            meta.create_gate(
                leak_once(format!("tv.{}.reg[{}]", temp_var_name, i)),
                |meta| {
                    let s_reg = meta.query_advice(s_reg, Rotation::cur());
                    let reg = meta
                        .query_advice(self.reg[RegName(i as _)], Rotation::cur());
                    let t_var_a = meta.query_advice(temp_var, Rotation::cur());

                    let table_max_len = meta.query_selector(self.table_max_len);

                    vec![table_max_len * s_reg * (reg - t_var_a)]
                },
            );
        }
    }

    fn reg_next_gate<F: FieldExt>(
        &self,
        meta: &mut ConstraintSystem<F>,
        reg_next: Registers<REG_COUNT, Column<Advice>>,
        temp_var: Column<Advice>,
        temp_var_name: &str,
    ) {
        for (i, s_reg_next) in reg_next.0.into_iter().enumerate() {
            meta.create_gate(
                leak_once(format!("tv.{}.reg[{}]", temp_var_name, i)),
                |meta| {
                    let s_reg = meta.query_advice(s_reg_next, Rotation::cur());
                    let reg_next = meta
                        .query_advice(self.reg[RegName(i as _)], Rotation::next());
                    let t_var_a = meta.query_advice(temp_var, Rotation::cur());

                    let time_next = meta.query_advice(self.time, Rotation::next());
                    let exe_len = meta.query_selector(self.exe_len);

                    vec![exe_len * time_next * s_reg * (reg_next - t_var_a)]
                },
            );
        }
    }

    fn immediate_gate<F: FieldExt>(
        &self,
        meta: &mut ConstraintSystem<F>,
        immediate_sel: Column<Advice>,
        temp_var: Column<Advice>,
        temp_var_name: &str,
    ) {
        meta.create_gate(leak_once(format!("tv.{}.a", temp_var_name)), |meta| {
            let s_immediate = meta.query_advice(immediate_sel, Rotation::cur());
            let immediate = meta.query_advice(self.immediate, Rotation::cur());
            let t_var_a = meta.query_advice(temp_var, Rotation::cur());

            let table_max_len = meta.query_selector(self.table_max_len);

            vec![table_max_len * s_immediate * (immediate - t_var_a)]
        });
    }

    fn vaddr_gate<F: FieldExt>(
        &self,
        meta: &mut ConstraintSystem<F>,
        vaddr_sel: Column<Advice>,
        temp_var: Column<Advice>,
        temp_var_name: &str,
    ) {
        meta.create_gate(leak_once(format!("tv.{}.vaddr", temp_var_name)), |meta| {
            let s_vaddr = meta.query_advice(vaddr_sel, Rotation::cur());
            let value = meta.query_advice(self.value, Rotation::cur());
            let t_var_a = meta.query_advice(temp_var, Rotation::cur());

            let table_max_len = meta.query_selector(self.table_max_len);

            vec![table_max_len * s_vaddr * (value - t_var_a)]
        });
    }

    fn one_gate<F: FieldExt>(
        &self,
        meta: &mut ConstraintSystem<F>,
        one_sel: Column<Advice>,
        temp_var: Column<Advice>,
        temp_var_name: &str,
    ) {
        meta.create_gate(leak_once(format!("tv.{}.one", temp_var_name)), |meta| {
            let s_one = meta.query_advice(one_sel, Rotation::cur());
            let t_var_a = meta.query_advice(temp_var, Rotation::cur());

            let table_max_len = meta.query_selector(self.table_max_len);

            vec![table_max_len * s_one * (Expression::Constant(F::one()) - t_var_a)]
        });
    }

    fn zero_gate<F: FieldExt>(
        &self,
        meta: &mut ConstraintSystem<F>,
        zero_sel: Column<Advice>,
        temp_var: Column<Advice>,
        temp_var_name: &str,
    ) {
        meta.create_gate(leak_once(format!("tv.{}.zero", temp_var_name)), |meta| {
            let s_zero = meta.query_advice(zero_sel, Rotation::cur());
            let t_var_a = meta.query_advice(temp_var, Rotation::cur());

            let table_max_len = meta.query_selector(self.table_max_len);

            vec![table_max_len * s_zero * t_var_a]
        });
    }

    fn max_word_gate<F: FieldExt>(
        &self,
        meta: &mut ConstraintSystem<F>,
        one_sel: Column<Advice>,
        temp_var: Column<Advice>,
        temp_var_name: &str,
    ) {
        meta.create_gate(
            leak_once(format!("tv.{}.max_word", temp_var_name)),
            |meta| {
                let s_max_word = meta.query_advice(one_sel, Rotation::cur());
                let t_var_a = meta.query_advice(temp_var, Rotation::cur());

                let table_max_len = meta.query_selector(self.table_max_len);

                vec![
                    table_max_len
                        * s_max_word
                        * (Expression::Constant(F::from_u128(
                            2u128.pow(WORD_BITS) - 1,
                        )) - t_var_a),
                ]
            },
        );
    }
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
        let config = {
            let time = meta.advice_column();

            let pc = meta.advice_column();

            let opcode = meta.advice_column();

            let immediate = meta.advice_column();

            let reg = Registers::init_with(|| meta.advice_column());

            // Temporary vars
            let a = meta.advice_column();
            let b = meta.advice_column();
            let c = meta.advice_column();
            let d = meta.advice_column();

            let flag = meta.advice_column();
            let address = meta.advice_column();
            let value = meta.advice_column();
            let temp_var_selectors =
                TempVarSelectors::new::<F, ConstraintSystem<F>>(meta);
            let table_max_len = meta.complex_selector();
            let exe_len = meta.complex_selector();

            let even_bits = EvenBitsTable::new(meta);

            let mut meta = TrackColumns::new(meta);

            Flag1Config::<WORD_BITS>::configure(
                &mut meta,
                exe_len,
                temp_var_selectors.out.flag1,
                c,
                flag,
            );

            let a_flag = meta.new_column();
            let flag2 = Flag2Config::<WORD_BITS>::configure(
                &mut meta,
                exe_len,
                temp_var_selectors.out.flag2,
                c,
                flag,
                a_flag,
            );

            let flag3_r = meta.new_column();
            let r_decompose = EvenBitsConfig::configure(
                &mut meta,
                flag3_r,
                &[temp_var_selectors.out.flag3],
                exe_len,
                even_bits,
            );
            let flag3 = Flag3Config::<WORD_BITS>::configure(
                &mut meta,
                exe_len,
                temp_var_selectors.out.flag3,
                a,
                b,
                c,
                flag,
                r_decompose,
            );

            SumConfig::<WORD_BITS>::configure(
                &mut meta,
                exe_len,
                temp_var_selectors.out.sum,
                a,
                b,
                c,
                d,
                flag,
            );

            ModConfig::<WORD_BITS>::configure(
                &mut meta,
                exe_len,
                temp_var_selectors.out.mod_,
                a,
                b,
                c,
                d,
                flag,
            );

            let a_decomp = EvenBitsConfig::configure(
                &mut meta,
                a,
                // The even_bits decomposition of `a` should be enabled anytime signed `a` is.
                &[
                    temp_var_selectors.out.and,
                    temp_var_selectors.out.xor,
                    temp_var_selectors.out.ssum,
                ],
                exe_len,
                even_bits,
            );

            let logic = LogicConfig::configure(
                &mut meta,
                even_bits,
                table_max_len,
                temp_var_selectors.out.and,
                temp_var_selectors.out.xor,
                temp_var_selectors.out.or,
                a_decomp,
                b,
                c,
            );

            ProdConfig::<WORD_BITS>::configure(
                &mut meta,
                exe_len,
                temp_var_selectors.out.prod,
                a,
                b,
                c,
                d,
            );

            let signed_a = SignedConfig::configure(
                &mut meta,
                exe_len,
                &[temp_var_selectors.out.ssum],
                logic.a,
                even_bits,
            );

            let b_decomp = EvenBitsConfig::configure(
                &mut meta,
                b,
                &[temp_var_selectors.out.sprod],
                exe_len,
                even_bits,
            );

            let signed_b = SignedConfig::configure(
                &mut meta,
                exe_len,
                &[temp_var_selectors.out.sprod],
                b_decomp,
                even_bits,
            );

            let c_decomp = EvenBitsConfig::configure(
                &mut meta,
                c,
                &[temp_var_selectors.out.ssum],
                exe_len,
                even_bits,
            );
            let signed_c = SignedConfig::configure(
                &mut meta,
                exe_len,
                &[temp_var_selectors.out.ssum],
                c_decomp,
                even_bits,
            );

            let ssum = SSumConfig::<WORD_BITS>::configure(
                &mut meta,
                exe_len,
                temp_var_selectors.out.ssum,
                signed_a,
                b,
                signed_c,
                d,
                flag,
            );

            let sprod = SProdConfig::<WORD_BITS>::configure(
                &mut meta,
                exe_len,
                temp_var_selectors.out.sprod,
                signed_a,
                signed_b,
                signed_c,
                d,
            );

            ExeConfig {
                table_max_len,
                exe_len,
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
                temp_var_selectors,
                even_bits,
                logic,
                ssum,
                sprod,
                intermediate: meta.1,
                flag2,
                flag3,
            }
        };

        config.temp_var_selectors.ch.unchanged_gate(
            meta,
            config.exe_len,
            config.reg,
            config.pc,
            config.flag,
        );

        {
            let SelectiorsA {
                pc_next,
                reg,
                reg_next,
                a,
                v_addr,
                non_det: _,
            } = config.temp_var_selectors.a;

            config.pc_next_gate(meta, pc_next, config.a, "a");
            config.reg_gate(meta, reg, config.a, "a");
            config.reg_next_gate(meta, reg_next, config.a, "a");
            config.immediate_gate(meta, a, config.a, "a");
            config.vaddr_gate(meta, v_addr, config.a, "a");

            // TODO use a lookup to check non_det is a valid word.
        }

        {
            let SelectiorsB {
                pc,
                pc_next,
                pc_plus_one,
                reg,
                reg_next,
                a,
                non_det: _,
                max_word,
            } = config.temp_var_selectors.b;

            config.pc_gate(meta, pc, config.b, "b");
            config.pc_next_gate(meta, pc_next, config.b, "b");
            config.pc_gate_plus_one(meta, pc_plus_one, config.b, "b");
            config.reg_gate(meta, reg, config.b, "b");
            config.reg_next_gate(meta, reg_next, config.b, "b");
            config.immediate_gate(meta, a, config.b, "b");
            config.max_word_gate(meta, max_word, config.b, "b");

            // TODO use a lookup to check non_det is a valid word.
        }

        {
            let SelectiorsC {
                reg,
                reg_next,
                a,
                non_det: _,
                zero,
            } = config.temp_var_selectors.c;

            config.reg_gate(meta, reg, config.c, "c");
            config.reg_next_gate(meta, reg_next, config.c, "c");
            config.immediate_gate(meta, a, config.c, "c");
            config.zero_gate(meta, zero, config.c, "c");

            // TODO use a lookup to check non_det is a valid word.
        }

        {
            let SelectiorsD {
                pc,
                reg,
                reg_next,
                a,
                non_det: _,
                zero,
                one,
            } = config.temp_var_selectors.d;

            config.pc_gate(meta, pc, config.d, "d");
            config.reg_gate(meta, reg, config.d, "d");
            config.reg_next_gate(meta, reg_next, config.d, "d");
            config.immediate_gate(meta, a, config.d, "d");
            config.zero_gate(meta, zero, config.d, "d");
            config.one_gate(meta, one, config.d, "d");

            // TODO use a lookup to check non_det is a valid word.
        }
        config
    }

    fn assign_trace(
        &self,
        mut layouter: impl Layouter<F>,
        trace: &Trace<WORD_BITS, REG_COUNT>,
    ) -> Result<(), Error> {
        let ExeConfig {
            table_max_len,
            exe_len,
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
            temp_var_selectors,
            even_bits: _,
            logic,
            ssum,
            sprod,
            intermediate: _,
            flag2,
            flag3,
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

                    for (offset, step) in trace.exe.iter().enumerate() {
                        for c in self.config.intermediate.iter() {
                            // Zero fill all the intermediate columns.
                            // We will reassign the ones we use.
                            // This works around the unassigned cell error.
                            //
                            // A better long term fix is improving the mock prover
                            // by using `with_selector` instead of the any `Selector` heuristic
                            region
                                .assign_advice(
                                    || "default fill",
                                    *c,
                                    offset,
                                    || Value::known(F::from(u64::MAX)),
                                )
                                .unwrap();
                        }

                        region
                            .assign_advice(
                                || format!("time: {}", step.time.0),
                                time,
                                offset,
                                || Value::known(F::from_u128(step.time.0 as u128)),
                            )
                            .unwrap();

                        region
                            .assign_advice(
                                || format!("pc: {}", step.pc.0),
                                pc,
                                offset,
                                || Value::known(F::from_u128(step.pc.0 as u128)),
                            )
                            .unwrap();

                        region
                            .assign_advice(
                                || format!("opcode: {}", step.instruction.opcode()),
                                opcode,
                                offset,
                                || {
                                    Value::known(F::from_u128(
                                        step.instruction.opcode(),
                                    ))
                                },
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
                                offset,
                                || Value::known(F::from_u128(immediate_v)),
                            )
                            .unwrap();

                        // assign registers
                        for ((rn, reg), v) in
                            reg.0.iter().enumerate().zip(step.regs.0)
                        {
                            region
                                .assign_advice(
                                    || format!("r{}: {}", rn, v.0),
                                    *reg,
                                    offset,
                                    || Value::known(F::from_u128(v.into())),
                                )
                                .unwrap();
                        }

                        region
                            .assign_advice(
                                || format!("flag: {}", step.flag),
                                flag,
                                offset,
                                || Value::known(F::from(step.flag)),
                            )
                            .unwrap();

                        // Assign temp vars and temp var selectors
                        {
                            let temp_var_selectors_row =
                                TempVarSelectorsRow::<REG_COUNT>::from(
                                    &step.instruction,
                                );

                            temp_var_selectors.push_cells(
                                &mut (&mut region, offset),
                                temp_var_selectors_row,
                            );

                            let (ta, tb, tc, td) = temp_var_selectors_row
                                .push_temp_var_vals::<F, WORD_BITS>(
                                    &trace.exe, offset,
                                );

                            let ta = F::from_u128(ta as u128);
                            let tb = F::from_u128(tb as u128);
                            let tc = F::from_u128(tc as u128);
                            let td = F::from_u128(td as u128);

                            region
                                .assign_advice(
                                    || format!("a: {:?}", ta),
                                    a,
                                    offset,
                                    || Value::known(ta),
                                )
                                .unwrap();
                            region
                                .assign_advice(
                                    || format!("b: {:?}", tb),
                                    b,
                                    offset,
                                    || Value::known(tb),
                                )
                                .unwrap();
                            region
                                .assign_advice(
                                    || format!("c: {:?}", tc),
                                    c,
                                    offset,
                                    || Value::known(tc),
                                )
                                .unwrap();
                            region
                                .assign_advice(
                                    || format!("d: {:?}", td),
                                    d,
                                    offset,
                                    || Value::known(td),
                                )
                                .unwrap();

                            // TODO only assign flags for relevant instructions.
                            flag2.assign_flag2(
                                &mut region,
                                tc,
                                F::from(
                                    trace
                                        .exe
                                        .get(offset + 1)
                                        .map(|s| s.flag)
                                        .unwrap_or(false),
                                ),
                                offset,
                            );

                            match step.instruction {
                                Instruction::And(_) => {
                                    logic.assign_and(&mut region, ta, tb, offset);
                                }
                                Instruction::Xor(_) => {
                                    logic.assign_xor(&mut region, ta, tb, offset);
                                }
                                Instruction::Or(_) => {
                                    logic.assign_or(&mut region, ta, tb, offset);
                                }
                                // SUM uses only temporary variables
                                Instruction::Add(_)
                                | Instruction::Sub(_)
                                | Instruction::Cmpa(_)
                                | Instruction::Cmpae(_) => {}
                                Instruction::Cmpg(_) | Instruction::Cmpge(_) => {
                                    ssum.assign_sum(&mut region, ta, tc, offset);
                                }
                                Instruction::SMulh(_) => sprod.assign_sprod(
                                    &mut region,
                                    ta,
                                    tb,
                                    tc,
                                    offset,
                                ),
                                Instruction::UMod(_) | Instruction::UDiv(_) => {
                                    flag3.assign_flag3(&mut region, ta, tc, offset);
                                }
                                Instruction::Mov(_) => {
                                    logic.assign_xor(&mut region, ta, tb, offset);
                                }

                                // TODO
                                _ => {}
                            }
                        }

                        {
                            // let addr = match step.instruction {
                            //     Instruction::LoadW(LoadW { a, .. })
                            //     | Instruction::StoreW(StoreW { a, .. }) => match a {
                            //         ImmediateOrRegName::Immediate(w) => w.0,
                            //         ImmediateOrRegName::RegName(r) => step.regs[r].0,
                            //     },
                            //     // We probably should not be assigning anything in these cases,
                            //     // but until the mock prover has more precise logic we have to.
                            //     _ => 0,
                            // };
                            let vaddr = step.v_addr.unwrap_or_default().0 as _;
                            region
                                .assign_advice(
                                    || format!("vaddr: {}", vaddr),
                                    value,
                                    offset,
                                    || Value::known(F::from_u128(vaddr)),
                                )
                                .unwrap();
                        }
                    }

                    region
                        .assign_advice(
                            || format!("Terminating time: {}", 0),
                            time,
                            trace.exe.len(),
                            || Value::known(F::zero()),
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
    type Config = ExeConfig<WORD_BITS, REG_COUNT>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        ExeChip::<F, WORD_BITS, REG_COUNT>::configure(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let exe_chip = ExeChip::<F, WORD_BITS, REG_COUNT>::construct(config);

        exe_chip
            .config
            .even_bits
            .alloc_table(&mut layouter)
            .unwrap();

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
    use proptest::{prop_compose, proptest};

    use crate::{
        circuits::tables::exe::ExeCircuit, test_utils::gen_proofs_and_verify,
        trace::*,
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
        ins: Instruction,
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
        let k = 1 + WORD_BITS / 2;
        let circuit = ExeCircuit::<WORD_BITS, REG_COUNT> { trace: Some(trace) };

        // Given the correct public input, our circuit will verify.
        let prover = MockProver::<Fp>::run(k, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
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
         (a in -2i32.pow(word_bits - 1)..2i32.pow(word_bits - 1) - 1)
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
    }
}
