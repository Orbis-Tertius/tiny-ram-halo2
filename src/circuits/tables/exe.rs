mod temp_vars;

use std::marker::PhantomData;

use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Chip, Layouter, Region, SimpleFloorPlanner, Value},
    plonk::{
        Advice, Circuit, Column, ConstraintSystem, Constraints, Error, Expression,
        Fixed, Selector,
    },
    poly::Rotation,
};

use crate::{
    assign::{NewColumn, TrackColumns},
    circuits::{
        flag1::Flag1Config, flag2::Flag2Config, flag3::Flag3Config,
        flag4::Flag4Config, logic::LogicConfig, modulo::ModConfig, prod::ProdConfig,
        shift::ShiftConfig, sprod::SProdConfig, ssum::SSumConfig, sum::SumConfig,
    },
    instructions::{opcode::OpCode, unit::Answer, Instruction, Shl, Shr},
    leak_once,
    trace::{RegName, Registers, Trace},
};

use self::temp_vars::TempVars;

use super::{
    aux::{
        out::Out,
        out_table::{CorrectOutConfig, OutTable},
        SelectorsA, SelectorsB, SelectorsC, SelectorsD, TempVarSelectorsRow,
    },
    even_bits::{EvenBitsConfig, EvenBitsTable},
    pow::PowTable,
    prog::ProgramLine,
    signed::SignedConfig,
    TableSelector,
};

pub struct ExeChip<F: FieldExt, const WORD_BITS: u32, const REG_COUNT: usize> {
    config: ExeConfig<WORD_BITS, REG_COUNT>,
    _marker: PhantomData<F>,
}

/// The both constant parameters `WORD_BITS`, `REG_COUNT` will always fit in a `u8`.
/// `u32`, and `usize`, were picked for convenience.
#[derive(Debug, Clone)]
pub struct ExeConfig<const WORD_BITS: u32, const REG_COUNT: usize> {
    /// A Selector that's enabled on only the first line of the Exe table
    first_line: Selector,
    pub extent: TableSelector,

    /// Instruction count
    time: Column<Fixed>,

    /// Program count
    pub pc: Column<Advice>,
    pub program_line: ProgramLine<WORD_BITS, REG_COUNT, Column<Advice>>,

    // State
    reg: Registers<REG_COUNT, Column<Advice>>,
    flag: Column<Advice>,

    /// Temporary variables a, b, c, d, and their even_bits decompositions.
    temp_vars: TempVars<WORD_BITS>,

    /// Output selectors
    out: Out<Column<Advice>>,

    // Auxiliary memory columns
    address: Column<Advice>,
    value: Column<Advice>,

    // t_link: Column<Advice>,
    // v_link: Column<Advice>,
    // v_init: Column<Advice>,
    // s: Column<Advice>,
    // l: Column<Advice>,
    logic: LogicConfig<WORD_BITS>,
    ssum: SSumConfig<WORD_BITS>,
    sprod: SProdConfig<WORD_BITS>,
    shift: ShiftConfig<WORD_BITS>,

    /// An implemention detail, used to default fill columns.
    intermediate: Vec<Column<Advice>>,

    // FLAG1 needs no extra advice.
    // flag1: Flag1Config,
    flag2: Flag2Config<WORD_BITS>,
    flag3: Flag3Config<WORD_BITS>,
    flag4: Flag4Config<WORD_BITS>,

    // Auxiliary entries used by mutually exclusive constraints.
    even_bits: EvenBitsTable<WORD_BITS>,
    pow_table: PowTable<WORD_BITS>,
    out_table: OutTable,
}

impl<const WORD_BITS: u32, const REG_COUNT: usize> ExeConfig<WORD_BITS, REG_COUNT> {
    /// The length of the Exe table is the same as the even bits table.
    ///
    /// The maximum trace length is `TABLE_LEN - 1`.
    /// The last row of the table must be padding to prove the trace ended with `Answer`.
    const TABLE_LEN: usize = 2usize.pow(WORD_BITS / 2);
    /// The execution trace is a contiguous block of rows starting at the first row of the Exe table.
    /// The execution trace is at least one row.
    /// The last row of the execution trace must contain the instruction Answer.
    ///
    /// Rows of the Exe table have been set `s_table = 1`.
    /// Rows of the execution trace have been set `s_trace = 1`.
    /// If the trace is shorter than the Exe table's length,
    /// the remaining rows must have been set `s_trace = 0`.
    ///
    /// We use three gates to enforce this.
    ///
    /// 1. `start_trace` gate:
    ///
    /// The first row of exe contains the first row of trace.
    /// (start_trace * 1 - s_trace)
    ///
    /// 2. `contiguous_trace` gate:
    ///
    /// This row and the next row must both be included or excluded from the s_trace.
    /// `let contiguous = (s_trace - trace_len_next)`
    ///
    /// Evaluates to 0 if row is part of the s_trace (s_trace = 1), and the instruction is `Answer`.
    /// `let may_change = (R - (s_trace * R) + opcode - answer::OP_CODE)`
    /// Where `R` is a constant greater than `Answer::OP_CODE / 2`.
    /// Note that `R` definition relies on the fact that `Answer` has the highest opcode of any instruction.
    ///
    /// The whole `contiguous_trace` gate guaranties the trace or the padding continues on the next row of the Exe table.
    /// Or the current line is part of the trace, and contains the instruction `Answer`.
    /// `s_table * contiguous * may_change`
    ///
    /// Note that this gate does not enforce that a trace ends with the instruction `Answer`.
    /// Nor does it enforce that row containing the instruction `Answer` is followed by padding.
    /// The former can be enforced by checking that the last line of the Exe table contains `s_trace = 0`
    /// The latter is enforced by including `trace_len_next` in the `Out` lookup.
    ///
    /// Without `may_change` the lookup is not sufficient to guarantee padding (rows with `s_trace = 0`)
    /// cannot be followed by part of the trace (rows with `s_trace = 1`).
    /// The `trace_len_next: s_table * s_trace * trace_len_next` looks up the default 0 when `s_trace = 0`.
    /// So the sequence: answer, padding, arbitrary instruction, would be allowed.
    // TODO enforce trace ends with `Answer 0`
    fn trace_len_gates<F: FieldExt>(&self, meta: &mut ConstraintSystem<F>) {
        meta.create_gate("start_trace", |meta| {
            let one = Expression::Constant(F::one());

            let first_line = meta.query_selector(self.first_line);

            let s_trace = meta.query_advice(self.extent.s_trace, Rotation::cur());

            let trace_starts = one - s_trace;
            let zeroed_pc = meta.query_advice(self.pc, Rotation::cur());
            let zeroed_flag = meta.query_advice(self.flag, Rotation::cur());
            let zeroed_regs =
                self.reg.map(|r| meta.query_advice(r, Rotation::cur())).0;

            Constraints::with_selector(
                first_line,
                [trace_starts, zeroed_pc, zeroed_flag]
                    .into_iter()
                    .chain(zeroed_regs)
                    .collect::<Vec<_>>(),
            )
        });

        meta.create_gate("contiguous_trace", |meta| {
            let answer_opcode = Expression::Constant(F::from(Answer::OP_CODE));
            // R could be anything `> answer::OP_CODE / 2`.
            let r = Expression::Constant(F::from(u64::MAX));

            let s_table = meta.query_selector(self.extent.s_table);

            let s_trace = meta.query_advice(self.extent.s_trace, Rotation::cur());
            let trace_len_next =
                meta.query_advice(self.extent.s_trace, Rotation::next());

            let opcode =
                meta.query_advice(self.program_line.opcode, Rotation::cur());

            let contiguous = s_trace.clone() - trace_len_next;
            let may_change = r.clone() - (s_trace * r) + opcode - answer_opcode;

            Constraints::with_selector(
                s_table,
                [Expression::SelectorExpression(Box::new(
                    contiguous * may_change,
                ))],
            )
        })
    }
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

            let s_table = meta.query_selector(self.extent.s_table);
            let s_trace = meta.query_advice(self.extent.s_trace, Rotation::next());

            Constraints::with_selector(
                s_table * s_trace * sa_pc_next,
                [(pc - t_var)],
            )
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

            let s_trace_next = self.extent.query_trace_next(meta);

            Constraints::with_selector(
                s_trace_next * sa_pc_next,
                [((pc + Expression::Constant(F::one())) - t_var)],
            )
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
                let s_trace_next = self.extent.query_trace_next(meta);

                Constraints::with_selector(
                    s_trace_next * sa_pc_next,
                    [(pc_next - t_var)],
                )
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

                    let s_trace = self.extent.query(meta);

                    Constraints::with_selector(s_trace * s_reg, [(reg - t_var_a)])
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
                    let s_reg_next = meta.query_advice(s_reg_next, Rotation::cur());
                    let reg_next = meta
                        .query_advice(self.reg[RegName(i as _)], Rotation::next());
                    let t_var_a = meta.query_advice(temp_var, Rotation::cur());

                    let s_trace_next = self.extent.query_trace_next(meta);

                    Constraints::with_selector(
                        s_trace_next * s_reg_next,
                        [(reg_next - t_var_a)],
                    )
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
            let immediate =
                meta.query_advice(self.program_line.immediate, Rotation::cur());
            let t_var_a = meta.query_advice(temp_var, Rotation::cur());

            let s_trace = self.extent.query(meta);

            Constraints::with_selector(
                s_trace * s_immediate,
                [(immediate - t_var_a)],
            )
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

            let s_table = meta.query_selector(self.extent.s_table);
            let s_trace = meta.query_advice(self.extent.s_trace, Rotation::cur());

            Constraints::with_selector(
                s_table * s_trace * s_vaddr,
                [(value - t_var_a)],
            )
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

            let s_table = meta.query_selector(self.extent.s_table);
            let s_trace = meta.query_advice(self.extent.s_trace, Rotation::cur());

            Constraints::with_selector(
                s_table * s_trace * s_one,
                [(Expression::Constant(F::one()) - t_var_a)],
            )
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

            let s_table = meta.query_selector(self.extent.s_table);
            let s_trace = meta.query_advice(self.extent.s_trace, Rotation::cur());

            Constraints::with_selector(s_table * s_trace * s_zero, [t_var_a])
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

                let s_table = meta.query_selector(self.extent.s_table);
                let s_trace =
                    meta.query_advice(self.extent.s_trace, Rotation::cur());

                Constraints::with_selector(
                    s_table * s_trace * s_max_word,
                    [
                        (Expression::Constant(F::from_u128(
                            2u128.pow(WORD_BITS) - 1,
                        )) - t_var_a),
                    ],
                )
            },
        );
    }

    fn configure_selectors_a<F: FieldExt>(&self, meta: &mut ConstraintSystem<F>) {
        let SelectorsA {
            pc_next,
            reg,
            reg_next,
            a,
            v_addr,
            non_det: _,
        } = self.program_line.temp_var_selectors.a;

        self.pc_next_gate(meta, pc_next, self.temp_vars.a.word, "a");
        self.reg_gate(meta, reg, self.temp_vars.a.word, "a");
        self.reg_next_gate(meta, reg_next, self.temp_vars.a.word, "a");
        self.immediate_gate(meta, a, self.temp_vars.a.word, "a");
        self.vaddr_gate(meta, v_addr, self.temp_vars.a.word, "a");
    }

    fn configure_selectors_b<F: FieldExt>(&self, meta: &mut ConstraintSystem<F>) {
        let SelectorsB {
            pc,
            pc_next,
            pc_plus_one,
            reg,
            reg_next,
            a,
            non_det: _,
            max_word,
        } = self.program_line.temp_var_selectors.b;

        self.pc_gate(meta, pc, self.temp_vars.b.word, "b");
        self.pc_next_gate(meta, pc_next, self.temp_vars.b.word, "b");
        self.pc_gate_plus_one(meta, pc_plus_one, self.temp_vars.b.word, "b");
        self.reg_gate(meta, reg, self.temp_vars.b.word, "b");
        self.reg_next_gate(meta, reg_next, self.temp_vars.b.word, "b");
        self.immediate_gate(meta, a, self.temp_vars.b.word, "b");
        self.max_word_gate(meta, max_word, self.temp_vars.b.word, "b");
    }

    fn configure_selectors_c<F: FieldExt>(&self, meta: &mut ConstraintSystem<F>) {
        let SelectorsC {
            reg,
            reg_next,
            a,
            non_det: _,
            zero,
        } = self.program_line.temp_var_selectors.c;

        self.reg_gate(meta, reg, self.temp_vars.c.word, "c");
        self.reg_next_gate(meta, reg_next, self.temp_vars.c.word, "c");
        self.immediate_gate(meta, a, self.temp_vars.c.word, "c");
        self.zero_gate(meta, zero, self.temp_vars.c.word, "c");
    }

    fn configure_selectors_d<F: FieldExt>(&self, meta: &mut ConstraintSystem<F>) {
        let SelectorsD {
            pc,
            reg,
            reg_next,
            a,
            non_det: _,
            zero,
            one,
        } = self.program_line.temp_var_selectors.d;

        self.pc_gate(meta, pc, self.temp_vars.d.word, "d");
        self.reg_gate(meta, reg, self.temp_vars.d.word, "d");
        self.reg_next_gate(meta, reg_next, self.temp_vars.d.word, "d");
        self.immediate_gate(meta, a, self.temp_vars.d.word, "d");
        self.zero_gate(meta, zero, self.temp_vars.d.word, "d");
        self.one_gate(meta, one, self.temp_vars.d.word, "d");
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
    pub fn construct(
        layouter: &mut impl Layouter<F>,
        config: ExeConfig<WORD_BITS, REG_COUNT>,
    ) -> Self {
        config.even_bits.alloc_table(layouter).unwrap();

        config.pow_table.alloc_table(layouter).unwrap();

        config.out_table.alloc_table(layouter).unwrap();

        Self {
            config,
            _marker: PhantomData,
        }
    }

    fn configure_instructions(
        meta: &mut ConstraintSystem<F>,
    ) -> ExeConfig<WORD_BITS, REG_COUNT> {
        let time = meta.fixed_column();

        let pc = meta.advice_column();

        let program_line = ProgramLine::configure::<F, _>(meta);

        let reg = Registers::init_with(|| meta.advice_column());

        let flag = meta.advice_column();
        let address = meta.advice_column();
        let value = meta.advice_column();
        let out = Out::new(|| meta.new_column());

        let first_line = meta.selector();
        let TableSelector { s_table, s_trace } = TableSelector::configure(meta);

        let even_bits = EvenBitsTable::configure(meta);
        let pow_table = PowTable::new(meta);
        let out_table = OutTable::new(meta);
        CorrectOutConfig::configure(
            meta,
            program_line.opcode,
            out,
            s_trace,
            s_table,
            out_table,
        );

        let mut meta = TrackColumns::new(meta);

        let temp_vars =
            TempVars::configure::<REG_COUNT, F>(&mut meta, s_table, out, even_bits);

        Flag1Config::<WORD_BITS>::configure(
            &mut meta,
            s_table,
            out.flag1,
            temp_vars.c.word,
            flag,
        );

        let a_flag = meta.new_column();
        let flag2 = Flag2Config::<WORD_BITS>::configure(
            &mut meta,
            s_table,
            out.flag2,
            temp_vars.c.word,
            flag,
            a_flag,
        );

        let flag3_r = meta.new_column();
        let r_decompose = EvenBitsConfig::configure(
            &mut meta,
            flag3_r,
            &[out.flag3, out.shift],
            s_table,
            even_bits,
        );
        let flag3 = Flag3Config::<WORD_BITS>::configure(
            &mut meta,
            s_table,
            out.flag3,
            temp_vars.a.word,
            temp_vars.b.word,
            temp_vars.c.word,
            flag,
            r_decompose,
        );

        SumConfig::<WORD_BITS>::configure(
            &mut meta,
            s_table,
            out.sum,
            temp_vars.a.word,
            temp_vars.b.word,
            temp_vars.c.word,
            temp_vars.d.word,
            flag,
        );

        ModConfig::<WORD_BITS>::configure(
            &mut meta,
            s_table,
            out.mod_,
            temp_vars.a.word,
            temp_vars.b.word,
            temp_vars.c.word,
            temp_vars.d.word,
            flag,
        );

        let a_decomp = EvenBitsConfig::configure(
            &mut meta,
            temp_vars.a.word,
            // The even_bits decomposition of `a` should be enabled anytime signed `a` is.
            &[out.and, out.xor, out.ssum],
            s_table,
            even_bits,
        );

        let logic = LogicConfig::configure(
            &mut meta,
            even_bits,
            s_table,
            out.and,
            out.xor,
            out.or,
            a_decomp,
            temp_vars.b.word,
            temp_vars.c.word,
        );

        ProdConfig::<WORD_BITS>::configure(
            &mut meta,
            s_table,
            out.prod,
            temp_vars.a.word,
            temp_vars.b.word,
            temp_vars.c.word,
            temp_vars.d.word,
        );

        let signed_a = SignedConfig::configure(
            &mut meta,
            s_table,
            &[out.ssum],
            logic.a,
            even_bits,
        );

        let b_decomp = EvenBitsConfig::configure(
            &mut meta,
            temp_vars.b.word,
            &[out.sprod],
            s_table,
            even_bits,
        );

        let signed_b = SignedConfig::configure(
            &mut meta,
            s_table,
            &[out.sprod],
            b_decomp,
            even_bits,
        );

        let c_decomp = EvenBitsConfig::configure(
            &mut meta,
            temp_vars.c.word,
            &[out.ssum],
            s_table,
            even_bits,
        );
        let signed_c = SignedConfig::configure(
            &mut meta,
            s_table,
            &[out.ssum],
            c_decomp,
            even_bits,
        );

        let ssum = SSumConfig::<WORD_BITS>::configure(
            &mut meta,
            s_table,
            out.ssum,
            signed_a,
            temp_vars.b.word,
            signed_c,
            temp_vars.d.word,
            flag,
        );

        let sprod = SProdConfig::<WORD_BITS>::configure(
            &mut meta,
            s_table,
            out.sprod,
            signed_a,
            signed_b,
            signed_c,
            temp_vars.d.word,
        );

        let a_shift = meta.new_column();
        let a_power = meta.new_column();
        let shift = ShiftConfig::configure(
            &mut meta,
            s_table,
            out.shift,
            temp_vars.a.word,
            temp_vars.b.word,
            temp_vars.c.word,
            temp_vars.d.word,
            a_shift,
            a_power,
            r_decompose,
            pow_table,
        );

        let lsb_b = meta.new_column();
        let b_flag = meta.new_column();
        let flag4 = Flag4Config::<WORD_BITS>::configure(
            &mut meta, s_table, out.flag4, signed_b, lsb_b, b_flag, flag,
        );

        ExeConfig {
            first_line,
            extent: TableSelector { s_table, s_trace },
            time,
            pc,
            program_line,
            reg,
            flag,
            temp_vars,
            out,
            address,
            value,
            logic,
            ssum,
            sprod,
            shift,
            intermediate: meta.1,
            flag2,
            flag3,
            flag4,
            even_bits,
            pow_table,
            out_table,
        }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<F>,
    ) -> ExeConfig<WORD_BITS, REG_COUNT> {
        let config = Self::configure_instructions(meta);

        config.program_line.temp_var_selectors.ch.unchanged_gate(
            meta,
            config.extent,
            config.reg,
            config.pc,
            config.flag,
        );

        config.trace_len_gates(meta);

        config.configure_selectors_a(meta);
        config.configure_selectors_b(meta);
        config.configure_selectors_c(meta);
        config.configure_selectors_d(meta);

        config
    }

    pub fn assign_trace(
        &self,
        mut layouter: impl Layouter<F>,
        trace: &Trace<WORD_BITS, REG_COUNT>,
    ) -> Result<(), Error> {
        let ExeConfig {
            first_line,
            extent,
            time,
            pc,
            program_line,
            reg,
            flag,
            temp_vars,
            out,
            address: _,
            value,
            logic,
            ssum,
            sprod,
            shift,
            intermediate: _,
            flag2,
            flag3,
            flag4,
            even_bits: _,
            pow_table: _,
            out_table: _,
        } = self.config;

        layouter
            .assign_region(
                || "Exe",
                |mut region: Region<'_, F>| {
                    first_line.enable(&mut region, 0).unwrap();

                    let table_len = ExeConfig::<WORD_BITS, REG_COUNT>::TABLE_LEN;

                    // Allocate the Exe table
                    extent.alloc_table_rows(&mut region, table_len)?;
                    for offset in 0..table_len {
                        // Time is 1 indexed.
                        region
                            .assign_fixed(
                                || format!("time: {}", offset + 1),
                                time,
                                offset,
                                || Value::known(F::from(offset as u64)),
                            )
                            .unwrap();
                    }

                    // Define the extent of the trace within the Exe table.
                    for offset in 0..trace.exe.len() {
                        extent.enable_row_of_table(&mut region, offset, true)?;
                    }

                    for (offset, step) in trace.exe.iter().enumerate() {
                        for c in self.config.intermediate.iter() {
                            // Zero fill all the intermediate columns.
                            // We will reassign the ones we use.
                            // This works around the unassigned cell error.
                            //
                            // FIXME(in progress)
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
                                || format!("pc: {}", step.pc.0),
                                pc,
                                offset,
                                || Value::known(F::from(step.pc.0 as u64)),
                            )
                            .unwrap();

                        region
                            .assign_advice(
                                || format!("opcode: {}", step.instruction.opcode()),
                                program_line.opcode,
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
                                program_line.immediate,
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

                            program_line.temp_var_selectors.assign_cells(
                                &mut region,
                                offset,
                                temp_var_selectors_row,
                            );

                            out.push_cells(
                                &mut region,
                                offset,
                                temp_var_selectors_row.out.convert(),
                            )
                            .unwrap();

                            let (ta, tb, tc, td) = temp_var_selectors_row
                                .push_temp_var_vals::<F, WORD_BITS>(
                                    &trace.exe, offset,
                                );

                            let ta = F::from_u128(ta as u128);
                            let tb = F::from_u128(tb as u128);

                            temp_vars.assign_temp_vars(
                                &mut region,
                                ta,
                                tb,
                                tc,
                                td,
                                offset,
                            );

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
                                Instruction::Xor(_) | Instruction::Cmpe(_) => {
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

                                Instruction::Shl(Shl { a, .. }) => {
                                    let shift_bits = a.get(&step.regs);
                                    shift.assign_shift(
                                        &mut region,
                                        shift_bits.0,
                                        offset,
                                    );
                                    flag4.assign_flag4(
                                        &mut region,
                                        tb.get_lower_128().try_into().unwrap(),
                                        true,
                                        offset,
                                    );
                                }
                                Instruction::Shr(Shr { a, .. }) => {
                                    let shift_bits = a.get(&step.regs);
                                    shift.assign_shift(
                                        &mut region,
                                        shift_bits.0,
                                        offset,
                                    );

                                    flag4.assign_flag4(
                                        &mut region,
                                        tb.get_lower_128().try_into().unwrap(),
                                        false,
                                        offset,
                                    );
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

                    extent.enable_row_of_table(
                        &mut region,
                        trace.exe.len(),
                        false,
                    )?;

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
        let exe_chip =
            ExeChip::<F, WORD_BITS, REG_COUNT>::construct(&mut layouter, config);

        if let Some(trace) = &self.trace {
            exe_chip.assign_trace(layouter.namespace(|| "Trace"), trace)?
        };
        Ok(())
    }
}

#[cfg(test)]
mod exe_tests {
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
