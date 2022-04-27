use halo2_proofs::{arithmetic::FieldExt, plonk};

use crate::{
    assign::{NewColumn, PushRow},
    trace::{self, *},
};

#[derive(Debug, Clone)]
pub struct ExeRow<const REG_COUNT: usize, C: Copy> {
    pub pc: C,
    pub immediate: C,
    pub regs: [C; REG_COUNT],
    // Page 34
    pub v_addr: C,
}

impl<const REG_COUNT: usize, C: Copy> ExeRow<REG_COUNT, C> {
    pub fn new<F: FieldExt, M>(meta: &mut M) -> ExeRow<REG_COUNT, C>
    where
        M: NewColumn<C>,
    {
        ExeRow {
            pc: NewColumn::new_column(meta),
            immediate: NewColumn::new_column(meta),
            regs: [0; REG_COUNT].map(|_| NewColumn::new_column(meta)),
            v_addr: NewColumn::new_column(meta),
        }
    }
}

/// This corresponds to sch in the paper.
/// A selector value of 1 denotes an unchanged cell.
#[derive(Debug, Clone, Copy)]
pub struct UnChangedSelectors<const REG_COUNT: usize, T> {
    pub regs: Registers<REG_COUNT, T>,
    pub pc: T,
    pub flag: T,
}

impl<const REG_COUNT: usize, T> UnChangedSelectors<REG_COUNT, T> {
    pub fn new(mut new_fn: impl FnMut() -> T) -> Self {
        UnChangedSelectors {
            regs: Registers([0usize; REG_COUNT].map(|_| new_fn())),
            pc: new_fn(),
            flag: new_fn(),
        }
    }

    fn push_cells<F: FieldExt, R: PushRow<F, T>>(
        self,
        region: &mut R,
        vals: UnChangedSelectors<REG_COUNT, bool>,
    ) -> Result<(), plonk::Error> {
        let Self { regs, pc, flag } = self;

        for (rc, rv) in regs.0.into_iter().zip(vals.regs.0.into_iter()) {
            region.push_cell(rc, rv.into()).unwrap();
        }
        region.push_cell(pc, vals.pc.into())?;
        region.push_cell(flag, vals.flag.into())?;

        Ok(())
    }

    fn convert<B: From<T>>(self) -> UnChangedSelectors<REG_COUNT, B> {
        UnChangedSelectors {
            regs: self.regs.convert(),
            pc: self.pc.into(),
            flag: self.flag.into(),
        }
    }
}

/// This corresponds to `sout` in the paper (page 24).
#[derive(Debug, Clone, Copy)]
pub struct Out<T> {
    /// logical
    pub and: T,
    pub xor: T,
    pub or: T,

    /// arithmetic
    pub sum: T,
    pub ssum: T,
    pub prod: T,
    pub sprod: T,
    pub mod_: T,

    pub shift: T,

    pub flag1: T,
    pub flag2: T,
    pub flag3: T,
    pub flag4: T,
}

impl<T> Out<T> {
    pub fn new(mut new_fn: impl FnMut() -> T) -> Out<T> {
        Out {
            and: new_fn(),
            xor: new_fn(),
            or: new_fn(),
            sum: new_fn(),
            prod: new_fn(),
            ssum: new_fn(),
            sprod: new_fn(),
            mod_: new_fn(),
            shift: new_fn(),
            flag1: new_fn(),
            flag2: new_fn(),
            flag3: new_fn(),
            flag4: new_fn(),
        }
    }
}

impl<C> Out<C> {
    fn push_cells<F: FieldExt, R: PushRow<F, C>>(
        self,
        region: &mut R,
        vals: Out<bool>,
    ) -> Result<(), plonk::Error> {
        let Self {
            and,
            xor,
            or,
            sum,
            prod,
            ssum,
            sprod,
            mod_,
            shift,
            flag1,
            flag2,
            flag3,
            flag4,
        } = self;

        region.push_cell(and, vals.and.into())?;
        region.push_cell(xor, vals.xor.into())?;
        region.push_cell(or, vals.or.into())?;
        region.push_cell(sum, vals.sum.into())?;
        region.push_cell(prod, vals.prod.into())?;
        region.push_cell(ssum, vals.ssum.into())?;
        region.push_cell(sprod, vals.sprod.into())?;
        region.push_cell(mod_, vals.mod_.into())?;
        region.push_cell(shift, vals.shift.into())?;
        region.push_cell(flag1, vals.flag1.into())?;
        region.push_cell(flag2, vals.flag2.into())?;
        region.push_cell(flag3, vals.flag3.into())?;
        region.push_cell(flag4, vals.flag4.into())?;

        Ok(())
    }
}

impl<T> Out<T> {
    fn convert<B: From<T>>(self) -> Out<B> {
        Out {
            and: self.and.into(),
            xor: self.xor.into(),
            or: self.or.into(),
            sum: self.sum.into(),
            prod: self.prod.into(),
            ssum: self.ssum.into(),
            sprod: self.sprod.into(),
            mod_: self.mod_.into(),
            shift: self.shift.into(),
            flag1: self.flag1.into(),
            flag2: self.flag2.into(),
            flag3: self.flag3.into(),
            flag4: self.flag4.into(),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct TempVarSelectors<const REG_COUNT: usize, C: Copy> {
    pub a: SelectiorsA<REG_COUNT, C>,
    pub b: SelectiorsB<REG_COUNT, C>,
    pub c: SelectiorsC<REG_COUNT, C>,
    pub d: SelectiorsD<REG_COUNT, C>,
    pub out: Out<C>,
    pub ch: UnChangedSelectors<REG_COUNT, C>,
}

impl<const REG_COUNT: usize, C: Copy> TempVarSelectors<REG_COUNT, C> {
    pub fn new<F: FieldExt, M>(meta: &mut M) -> TempVarSelectors<REG_COUNT, C>
    where
        M: NewColumn<C>,
    {
        TempVarSelectors {
            a: SelectiorsA::new_columns::<F, M>(meta),
            b: SelectiorsB::new_columns::<F, M>(meta),
            c: SelectiorsC::new_columns::<F, M>(meta),
            d: SelectiorsD::new_columns::<F, M>(meta),
            out: Out::new(|| meta.new_column()),
            ch: UnChangedSelectors::new(|| meta.new_column()),
        }
    }

    pub fn push_cells<F: FieldExt, R: PushRow<F, C>>(
        self,
        region: &mut R,
        vals: TempVarSelectorsRow<REG_COUNT>,
    ) {
        let Self {
            a,
            b,
            c,
            d,
            out,
            ch,
        } = self;
        a.push_cells(region, vals.a.into());
        b.push_cells(region, vals.b.into());
        c.push_cells(region, vals.c.into());
        d.push_cells(region, vals.d.into());
        out.push_cells(region, vals.out.convert()).unwrap();
        ch.push_cells(region, vals.ch.convert()).unwrap();
    }
}

#[derive(Debug, Clone, Copy)]
pub struct TempVarSelectorsRow<const REG_COUNT: usize> {
    pub a: SelectionA,
    pub b: SelectionB,
    pub c: SelectionC,
    pub d: SelectionD,
    pub out: Out<bool>,
    pub ch: UnChangedSelectors<REG_COUNT, bool>,
}

impl<const REG_COUNT: usize> From<&trace::Instruction>
    for TempVarSelectorsRow<REG_COUNT>
{
    fn from(inst: &trace::Instruction) -> Self {
        let out = Out {
            and: false,
            xor: false,
            or: false,
            sum: false,
            prod: false,
            ssum: false,
            sprod: false,
            mod_: false,
            shift: false,
            flag1: false,
            flag2: false,
            flag3: false,
            flag4: false,
        };
        let ch = UnChangedSelectors {
            regs: Registers([true; REG_COUNT]),
            pc: true,
            flag: true,
        };

        match *inst {
            // Reference Page 27, Fig. 3
            trace::Instruction::And(And { ri, rj, .. }) => Self {
                a: SelectionA::A,
                b: SelectionB::Reg(rj),
                c: SelectionC::RegN(ri),
                d: SelectionD::Unset,
                out: Out {
                    and: true,
                    flag1: true,
                    flag2: true,
                    ..out
                },
                ch: UnChangedSelectors {
                    regs: ch.regs.set(ri, false),
                    flag: false,
                    ..ch
                },
            },
            trace::Instruction::Or(Or { ri, rj, .. }) => Self {
                a: SelectionA::A,
                b: SelectionB::Reg(rj),
                c: SelectionC::RegN(ri),
                d: SelectionD::Unset,
                out: Out {
                    or: true,
                    flag1: true,
                    flag2: true,
                    ..out
                },
                ch: UnChangedSelectors {
                    regs: ch.regs.set(ri, false),
                    flag: false,
                    ..ch
                },
            },
            trace::Instruction::Xor(Xor { ri, rj, .. }) => Self {
                a: SelectionA::A,
                b: SelectionB::Reg(rj),
                c: SelectionC::RegN(ri),
                d: SelectionD::Unset,
                out: Out {
                    xor: true,
                    flag1: true,
                    flag2: true,
                    ..out
                },
                ch: UnChangedSelectors {
                    regs: ch.regs.set(ri, false),
                    flag: false,
                    ..ch
                },
            },

            trace::Instruction::Not(Not { ri, .. }) => Self {
                a: SelectionA::A,
                b: SelectionB::AllBitsSet,
                c: SelectionC::RegN(ri),
                d: SelectionD::Unset,
                out: Out {
                    xor: true,
                    flag1: true,
                    flag2: true,
                    ..out
                },
                ch: UnChangedSelectors {
                    regs: ch.regs.set(ri, false),
                    flag: false,
                    ..ch
                },
            },
            // Reference Page 27, Fig. 4
            trace::Instruction::Add(Add { ri, rj, .. }) => Self {
                a: SelectionA::A,
                b: SelectionB::Reg(rj),
                c: SelectionC::RegN(ri),
                d: SelectionD::Zero,
                out: Out { sum: true, ..out },
                ch: UnChangedSelectors {
                    regs: ch.regs.set(ri, false),
                    flag: false,
                    ..ch
                },
            },
            trace::Instruction::Sub(Sub { ri, rj, .. }) => Self {
                a: SelectionA::A,
                b: SelectionB::RegN(ri),
                c: SelectionC::Reg(rj),
                d: SelectionD::Zero,
                out: Out { sum: true, ..out },
                ch: UnChangedSelectors {
                    regs: ch.regs.set(ri, false),
                    flag: false,
                    ..ch
                },
            },
            trace::Instruction::Mul(Mul { ri, rj, .. }) => Self {
                a: SelectionA::A,
                b: SelectionB::Reg(rj),
                c: SelectionC::TempVarC,
                d: SelectionD::RegN(ri),
                out: Out {
                    prod: true,
                    flag1: true,
                    flag2: true,
                    ..out
                },
                ch: UnChangedSelectors {
                    regs: ch.regs.set(ri, false),
                    flag: false,
                    ..ch
                },
            },
            trace::Instruction::UMulh(UMulh { ri, rj, .. }) => Self {
                a: SelectionA::A,
                b: SelectionB::Reg(rj),
                c: SelectionC::RegN(ri),
                d: SelectionD::TempVarD,
                out: Out {
                    prod: true,
                    flag1: true,
                    flag2: true,
                    ..out
                },
                ch: UnChangedSelectors {
                    regs: ch.regs.set(ri, false),
                    flag: false,
                    ..ch
                },
            },
            trace::Instruction::SMulh(SMulh { ri, rj, .. }) => Self {
                a: SelectionA::A,
                b: SelectionB::Reg(rj),
                c: SelectionC::RegN(ri),
                d: SelectionD::TempVarD,
                out: Out {
                    sprod: true,
                    flag1: true,
                    flag2: true,
                    ..out
                },
                ch: UnChangedSelectors {
                    regs: ch.regs.set(ri, false),
                    flag: false,
                    ..ch
                },
            },
            trace::Instruction::UDiv(UDiv { ri, rj, .. }) => Self {
                a: SelectionA::A,
                b: SelectionB::RegN(ri),
                c: SelectionC::A,
                d: SelectionD::Reg(rj),
                out: Out {
                    mod_: true,
                    flag1: true,
                    flag2: true,
                    flag3: true,
                    ..out
                },
                ch: UnChangedSelectors {
                    regs: ch.regs.set(ri, false),
                    flag: false,
                    ..ch
                },
            },
            trace::Instruction::UMod(UMod { ri, rj, .. }) => Self {
                a: SelectionA::RegN(ri),
                b: SelectionB::TempVarB,
                c: SelectionC::A,
                d: SelectionD::Reg(rj),
                out: Out {
                    mod_: true,
                    flag1: true,
                    flag2: true,
                    flag3: true,
                    ..out
                },
                ch: UnChangedSelectors {
                    regs: ch.regs.set(ri, false),
                    flag: false,
                    ..ch
                },
            },
            trace::Instruction::Shl(Shl { ri, rj, .. }) => Self {
                a: SelectionA::A,
                b: SelectionB::Reg(rj),
                c: SelectionC::TempVarC,
                d: SelectionD::RegN(ri),
                out: Out {
                    shift: true,
                    flag4: true,
                    ..out
                },
                ch: UnChangedSelectors {
                    regs: ch.regs.set(ri, false),
                    flag: false,
                    ..ch
                },
            },
            trace::Instruction::Shr(Shr { ri, rj, .. }) => Self {
                a: SelectionA::A,
                b: SelectionB::Reg(rj),
                c: SelectionC::RegN(ri),
                d: SelectionD::TempVarD,
                out: Out {
                    shift: true,
                    flag4: true,
                    ..out
                },
                ch: UnChangedSelectors {
                    regs: ch.regs.set(ri, false),
                    flag: false,
                    ..ch
                },
            },

            // Reference Page 33, Fig. 8
            trace::Instruction::Cmpe(Cmpe { ri, .. }) => Self {
                a: SelectionA::A,
                b: SelectionB::Reg(ri),
                c: SelectionC::TempVarC,
                d: SelectionD::Unset,
                out: Out {
                    xor: true,
                    flag1: true,
                    flag2: true,
                    ..out
                },
                ch: UnChangedSelectors { flag: false, ..ch },
            },
            trace::Instruction::Cmpa(Cmpa { ri, .. }) => Self {
                a: SelectionA::Reg(ri),
                b: SelectionB::TempVarB,
                c: SelectionC::A,
                d: SelectionD::Zero,
                out: Out { sum: true, ..out },
                ch: UnChangedSelectors { flag: false, ..ch },
            },
            trace::Instruction::Cmpae(Cmpae { ri, .. }) => Self {
                a: SelectionA::Reg(ri),
                b: SelectionB::TempVarB,
                c: SelectionC::A,
                d: SelectionD::One,
                out: Out { sum: true, ..out },
                ch: UnChangedSelectors { flag: false, ..ch },
            },
            trace::Instruction::Cmpg(Cmpg { ri, .. }) => Self {
                a: SelectionA::Reg(ri),
                b: SelectionB::TempVarB,
                c: SelectionC::A,
                d: SelectionD::Zero,
                out: Out { ssum: true, ..out },
                ch: UnChangedSelectors { flag: false, ..ch },
            },
            trace::Instruction::Cmpge(Cmpge { ri, .. }) => Self {
                a: SelectionA::Reg(ri),
                b: SelectionB::TempVarB,
                c: SelectionC::A,
                d: SelectionD::One,
                out: Out { ssum: true, ..out },
                ch: UnChangedSelectors { flag: false, ..ch },
            },
            trace::Instruction::Mov(Mov { ri, .. }) => Self {
                a: SelectionA::A,
                b: SelectionB::RegN(ri),
                c: SelectionC::Zero,
                d: SelectionD::Unset,
                out: Out { xor: true, ..out },
                ch: UnChangedSelectors {
                    regs: ch.regs.set(ri, false),
                    ..ch
                },
            },
            trace::Instruction::CMov(CMov { ri, .. }) => Self {
                a: SelectionA::RegN(ri),
                b: SelectionB::A,
                c: SelectionC::Zero,
                // The table on page 34 call for rj,t.
                // It's a typo, on page 33 d = ri,t.
                d: SelectionD::Reg(ri),
                out: Out { mod_: true, ..out },
                ch: UnChangedSelectors {
                    regs: ch.regs.set(ri, false),
                    ..ch
                },
            },
            trace::Instruction::Jmp(_) => Self {
                a: SelectionA::A,
                b: SelectionB::PcN,
                c: SelectionC::Zero,
                d: SelectionD::Unset,
                out: Out { xor: true, ..out },
                ch: UnChangedSelectors { pc: false, ..ch },
            },
            trace::Instruction::CJmp(_) => Self {
                a: SelectionA::PcN,
                b: SelectionB::A,
                c: SelectionC::Zero,
                d: SelectionD::PcPlusOne,
                out: Out { mod_: true, ..out },
                ch: UnChangedSelectors { pc: false, ..ch },
            },
            trace::Instruction::CnJmp(_) => Self {
                a: SelectionA::PcN,
                b: SelectionB::PcPlusOne,
                c: SelectionC::Zero,
                d: SelectionD::A,
                out: Out { mod_: true, ..out },
                ch: UnChangedSelectors { pc: false, ..ch },
            },

            trace::Instruction::LoadW(LoadW { ri, .. }) => Self {
                a: SelectionA::VAddr,
                b: SelectionB::Reg(ri),
                c: SelectionC::Zero,
                d: SelectionD::Zero,
                out: Out { xor: true, ..out },
                ch,
            },
            trace::Instruction::StoreW(StoreW { ri, .. }) => Self {
                a: SelectionA::VAddr,
                b: SelectionB::RegN(ri),
                c: SelectionC::Zero,
                d: SelectionD::Zero,
                out: Out { xor: true, ..out },
                ch: UnChangedSelectors {
                    regs: ch.regs.set(ri, false),
                    ..ch
                },
            },

            // TODO it is unclear what should be in Answer's selection vectors.
            // Reference page 35
            trace::Instruction::Answer(_) => Self {
                a: SelectionA::A,
                b: SelectionB::Pc,
                c: SelectionC::Zero,
                d: SelectionD::Zero,
                out,
                ch,
            },
        }
    }
}

/// Variants ending with `N` refer to the next row (`t+1).
#[derive(Debug, Clone, Copy)]
pub enum SelectionA {
    PcN,

    Reg(RegName),
    RegN(RegName),

    A,

    VAddr,
    /// Selects the temporary var associated with this selection vector.
    TempVarA,
}

/// Use `SelectiorsA::new_*` to construct correct selectors.
/// Fields ending with `next` refer to the next row (`t+1).
#[derive(Debug, Clone, Copy)]
pub struct SelectiorsA<const REG_COUNT: usize, C: Copy> {
    pub pc_next: C,

    pub reg: Registers<REG_COUNT, C>,
    pub reg_next: Registers<REG_COUNT, C>,

    pub a: C,

    pub v_addr: C,
    /// Selects the temporary var associated with this selection vector.
    pub temp_var_a: C,
}

impl<const REG_COUNT: usize> From<SelectionA> for SelectiorsA<REG_COUNT, bool> {
    fn from(s: SelectionA) -> Self {
        let mut r = SelectiorsA {
            pc_next: false,
            reg: Registers([false; REG_COUNT]),
            reg_next: Registers([false; REG_COUNT]),
            a: false,
            v_addr: false,
            temp_var_a: false,
        };
        match s {
            SelectionA::Reg(i) => r.reg[i] = true,
            SelectionA::RegN(i) => r.reg_next[i] = true,
            SelectionA::A => r.a = true,
            SelectionA::TempVarA => r.temp_var_a = true,
            SelectionA::PcN => r.pc_next = true,
            SelectionA::VAddr => r.v_addr = true,
        };
        r
    }
}

impl<const REG_COUNT: usize, C: Copy> SelectiorsA<REG_COUNT, C> {
    fn new_columns<F: FieldExt, M>(meta: &mut M) -> Self
    where
        M: NewColumn<C>,
    {
        SelectiorsA {
            pc_next: meta.new_column(),
            // Do not replace with `[meta.new_column(); REG_COUNT]` it's not equivalent.
            reg: [0; REG_COUNT].map(|_| meta.new_column()).into(),
            reg_next: [0; REG_COUNT].map(|_| meta.new_column()).into(),
            a: meta.new_column(),
            v_addr: meta.new_column(),
            temp_var_a: meta.new_column(),
        }
    }
}

impl<const REG_COUNT: usize, C: Copy> SelectiorsA<REG_COUNT, C> {
    fn push_cells<F: FieldExt, R: PushRow<F, C>>(
        self,
        region: &mut R,
        vals: SelectiorsA<REG_COUNT, bool>,
    ) {
        let Self {
            pc_next,
            reg,
            reg_next,
            a,
            v_addr,
            temp_var_a,
        } = self;

        region.push_cell(pc_next, vals.pc_next.into()).unwrap();

        for (rc, rv) in reg.0.into_iter().zip(vals.reg.0.into_iter()) {
            region.push_cell(rc, rv.into()).unwrap();
        }
        for (rc, rv) in reg_next.0.into_iter().zip(vals.reg_next.0.into_iter()) {
            region.push_cell(rc, rv.into()).unwrap();
        }

        region.push_cell(a, vals.a.into()).unwrap();
        region.push_cell(v_addr, vals.v_addr.into()).unwrap();
        region
            .push_cell(temp_var_a, vals.temp_var_a.into())
            .unwrap();
    }
}

/// Variants ending with `N` refer to the next row (`t+1).
#[derive(Debug, Clone, Copy)]
pub enum SelectionB {
    Pc,
    PcN,
    PcPlusOne,

    Reg(RegName),
    RegN(RegName),

    A,
    /// Selects the temporary var associated with this selection vector.
    TempVarB,

    One,
    /// 2^W − 1
    AllBitsSet,
}

/// Use `SelectiorsA::new_*` to construct correct selectors.
/// Fields ending with `next` refer to the next row (`t+1).
#[derive(Debug, Clone, Copy)]
pub struct SelectiorsB<const REG_COUNT: usize, C: Copy> {
    pub pc: C,
    pub pc_next: C,

    pub pc_plus_one: C,

    pub reg: Registers<REG_COUNT, C>,
    pub reg_next: Registers<REG_COUNT, C>,

    pub a: C,

    /// Selects the temporary var associated with this selection vector.
    pub temp_var_b: C,

    pub one: C,
    pub all_bits_set: C,
}

impl<const REG_COUNT: usize, C: Copy> SelectiorsB<REG_COUNT, C> {
    fn new_columns<F: FieldExt, M>(meta: &mut M) -> Self
    where
        M: NewColumn<C>,
    {
        SelectiorsB {
            pc: meta.new_column(),
            pc_next: meta.new_column(),
            pc_plus_one: meta.new_column(),
            // Do not replace with `[meta.new_column(); REG_COUNT]` it's not equivalent.
            reg: Registers([0; REG_COUNT].map(|_| meta.new_column())),
            reg_next: Registers([0; REG_COUNT].map(|_| meta.new_column())),
            a: meta.new_column(),
            temp_var_b: meta.new_column(),
            one: meta.new_column(),
            all_bits_set: meta.new_column(),
        }
    }
}

impl<const REG_COUNT: usize> From<SelectionB> for SelectiorsB<REG_COUNT, bool> {
    fn from(s: SelectionB) -> Self {
        let mut r = SelectiorsB {
            pc: false,
            pc_next: false,
            pc_plus_one: false,
            reg: Registers([false; REG_COUNT]),
            reg_next: Registers([false; REG_COUNT]),
            a: false,
            temp_var_b: false,
            one: false,
            all_bits_set: false,
        };
        match s {
            SelectionB::Pc => r.pc = true,
            SelectionB::PcN => r.pc_next = true,
            SelectionB::PcPlusOne => r.pc_next = true,
            SelectionB::Reg(i) => r.reg[i] = true,
            SelectionB::RegN(i) => r.reg_next[i] = true,
            SelectionB::A => r.a = true,
            SelectionB::TempVarB => r.temp_var_b = true,
            SelectionB::One => r.one = true,
            SelectionB::AllBitsSet => r.all_bits_set = true,
        };
        r
    }
}

impl<const REG_COUNT: usize, C: Copy> SelectiorsB<REG_COUNT, C> {
    fn push_cells<F: FieldExt, R: PushRow<F, C>>(
        self,
        region: &mut R,
        vals: SelectiorsB<REG_COUNT, bool>,
    ) {
        let Self {
            pc,
            pc_next,
            pc_plus_one,
            reg,
            reg_next,
            a,
            temp_var_b,
            one,
            all_bits_set,
        } = self;

        region.push_cell(pc, vals.pc.into()).unwrap();
        region.push_cell(pc_next, vals.pc_next.into()).unwrap();
        region
            .push_cell(pc_plus_one, vals.pc_plus_one.into())
            .unwrap();

        for (rc, rv) in reg.0.into_iter().zip(vals.reg.0.into_iter()) {
            region.push_cell(rc, rv.into()).unwrap();
        }
        for (rc, rv) in reg_next.0.into_iter().zip(vals.reg_next.0.into_iter()) {
            region.push_cell(rc, rv.into()).unwrap();
        }

        region.push_cell(a, vals.a.into()).unwrap();
        region.push_cell(one, vals.one.into()).unwrap();
        region
            .push_cell(all_bits_set, vals.all_bits_set.into())
            .unwrap();
        region
            .push_cell(temp_var_b, vals.temp_var_b.into())
            .unwrap();
    }
}

/// Variants ending with `N` refer to the next row (`t+1).
#[derive(Debug, Clone, Copy)]
pub enum SelectionC {
    Reg(RegName),
    RegN(RegName),

    A,

    /// Selects the temporary var associated with this selection vector.
    TempVarC,
    Zero,
}

/// Use `SelectiorsA::new_*` to construct correct selectors.
/// Fields ending with `next` refer to the next row (`t+1).
#[derive(Debug, Clone, Copy)]
pub struct SelectiorsC<const REG_COUNT: usize, C: Copy> {
    pub reg: Registers<REG_COUNT, C>,
    pub reg_next: Registers<REG_COUNT, C>,

    pub a: C,

    /// Selects the temporary var associated with this selection vector.
    pub temp_var_c: C,

    pub zero: C,
}

impl<const REG_COUNT: usize, C: Copy> SelectiorsC<REG_COUNT, C> {
    fn new_columns<F: FieldExt, M>(meta: &mut M) -> Self
    where
        M: NewColumn<C>,
    {
        SelectiorsC {
            // Do not replace with `[meta.new_column(); REG_COUNT]` it's not equivalent.
            reg: Registers([0; REG_COUNT].map(|_| meta.new_column())),
            reg_next: Registers([0; REG_COUNT].map(|_| meta.new_column())),
            a: meta.new_column(),
            temp_var_c: meta.new_column(),
            zero: meta.new_column(),
        }
    }
}

impl<const REG_COUNT: usize> From<SelectionC> for SelectiorsC<REG_COUNT, bool> {
    fn from(s: SelectionC) -> Self {
        let mut r = SelectiorsC {
            reg: Registers([false; REG_COUNT]),
            reg_next: Registers([false; REG_COUNT]),
            a: false,
            temp_var_c: false,
            zero: false,
        };
        match s {
            SelectionC::Reg(i) => r.reg[i] = true,
            SelectionC::RegN(i) => r.reg_next[i] = true,
            SelectionC::A => r.a = true,
            SelectionC::TempVarC => r.temp_var_c = true,
            SelectionC::Zero => r.zero = true,
        };
        r
    }
}

impl<const REG_COUNT: usize, C: Copy> SelectiorsC<REG_COUNT, C> {
    fn push_cells<F: FieldExt, R: PushRow<F, C>>(
        self,
        region: &mut R,
        vals: SelectiorsC<REG_COUNT, bool>,
    ) {
        let Self {
            reg,
            reg_next,
            a,
            temp_var_c,
            zero,
        } = self;

        for (rc, rv) in reg.0.into_iter().zip(vals.reg.0.into_iter()) {
            region.push_cell(rc, rv.into()).unwrap();
        }
        for (rc, rv) in reg_next.0.into_iter().zip(vals.reg_next.0.into_iter()) {
            region.push_cell(rc, rv.into()).unwrap();
        }

        region.push_cell(a, vals.a.into()).unwrap();
        region.push_cell(zero, vals.zero.into()).unwrap();
        region
            .push_cell(temp_var_c, vals.temp_var_c.into())
            .unwrap();
    }
}

/// Variants ending with `N` refer to the next row (`t+1).
#[derive(Debug, Clone, Copy)]
pub enum SelectionD {
    Pc,
    PcPlusOne,

    Reg(RegName),
    RegN(RegName),

    A,

    /// Selects the temporary var associated with this selection vector.
    TempVarD,

    Zero,
    One,
    // No bit is set in this selection vector.
    // Denoted `/` in the arya paper.
    Unset,
}

/// Use `SelectiorsD::new_*` and From<SelectionD> to construct correct selectors.
/// Fields ending with `next` refer to the next row (`t+1).
#[derive(Debug, Clone, Copy)]
pub struct SelectiorsD<const REG_COUNT: usize, C: Copy> {
    pub pc: C,
    pub pc_plus_one: C,

    pub reg: Registers<REG_COUNT, C>,
    pub reg_next: Registers<REG_COUNT, C>,

    pub a: C,

    /// Selects the temporary var associated with this selection vector.
    pub temp_var_d: C,

    pub zero: C,
    pub one: C,
}

impl<const REG_COUNT: usize, C: Copy> SelectiorsD<REG_COUNT, C> {
    fn new_columns<F: FieldExt, M>(meta: &mut M) -> Self
    where
        M: NewColumn<C>,
    {
        SelectiorsD {
            // Do not replace with `[meta.new_column(); REG_COUNT]` it's not equivalent.
            pc: meta.new_column(),
            pc_plus_one: meta.new_column(),

            reg: Registers([0; REG_COUNT].map(|_| meta.new_column())),
            reg_next: Registers([0; REG_COUNT].map(|_| meta.new_column())),
            a: meta.new_column(),
            temp_var_d: meta.new_column(),
            zero: meta.new_column(),
            one: meta.new_column(),
        }
    }
}

impl<const REG_COUNT: usize> From<SelectionD> for SelectiorsD<REG_COUNT, bool> {
    fn from(s: SelectionD) -> Self {
        let mut r = SelectiorsD {
            pc: false,
            pc_plus_one: false,
            reg: Registers([false; REG_COUNT]),
            reg_next: Registers([false; REG_COUNT]),
            a: false,
            temp_var_d: false,
            zero: false,
            one: false,
        };
        match s {
            SelectionD::Pc => r.pc = true,
            SelectionD::PcPlusOne => r.pc_plus_one = true,
            SelectionD::Reg(i) => r.reg[i] = true,
            SelectionD::RegN(i) => r.reg_next[i] = true,
            SelectionD::A => r.a = true,
            SelectionD::TempVarD => r.temp_var_d = true,
            SelectionD::Zero => r.zero = true,
            SelectionD::One => r.one = true,
            SelectionD::Unset => (),
        };
        r
    }
}

impl<const REG_COUNT: usize, C: Copy> SelectiorsD<REG_COUNT, C> {
    fn push_cells<F: FieldExt, R: PushRow<F, C>>(
        self,
        region: &mut R,
        vals: SelectiorsD<REG_COUNT, bool>,
    ) {
        let Self {
            pc,
            pc_plus_one,
            reg,
            reg_next,
            a,
            temp_var_d,
            zero,
            one,
        } = self;

        region.push_cell(pc, vals.pc.into()).unwrap();
        region
            .push_cell(pc_plus_one, vals.pc_plus_one.into())
            .unwrap();

        for (rc, rv) in reg.0.into_iter().zip(vals.reg.0.into_iter()) {
            region.push_cell(rc, rv.into()).unwrap();
        }
        for (rc, rv) in reg_next.0.into_iter().zip(vals.reg_next.0.into_iter()) {
            region.push_cell(rc, rv.into()).unwrap();
        }

        region.push_cell(a, vals.a.into()).unwrap();
        region.push_cell(zero, vals.zero.into()).unwrap();
        region.push_cell(one, vals.one.into()).unwrap();
        region
            .push_cell(temp_var_d, vals.temp_var_d.into())
            .unwrap();
    }
}
