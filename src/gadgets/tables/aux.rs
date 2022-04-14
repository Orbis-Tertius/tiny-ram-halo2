use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{AssignedCell, Region},
    plonk::{Advice, Column, ColumnType, ConstraintSystem, Selector},
};

use crate::{
    assign::NewColumn,
    trace::{self, And, LoadW, RegName, Registers, StoreW},
};

#[derive(Debug, Clone, Copy)]
pub struct ExeRow<const REG_COUNT: usize, C: ColumnType> {
    pub pc: Column<C>,
    pub immediate: Column<C>,
    pub regs: [Column<C>; REG_COUNT],
    // Page 34
    pub v_addr: Column<C>,
}

impl<const REG_COUNT: usize, C: ColumnType> ExeRow<REG_COUNT, C> {
    pub fn new<F: FieldExt>(meta: &mut ConstraintSystem<F>) -> ExeRow<REG_COUNT, C>
    where
        ConstraintSystem<F>: NewColumn<C>,
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
    pub prog: T,
    pub ssum: T,
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
            prog: new_fn(),
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

#[derive(Debug, Clone, Copy)]
pub struct TempVarSelectors<const REG_COUNT: usize, C: ColumnType> {
    pub a: SelectiorsA<REG_COUNT, Column<C>>,
    pub b: SelectiorsB<REG_COUNT, Column<C>>,
    pub c: SelectiorsC<REG_COUNT, Column<C>>,
    pub d: SelectiorsD<REG_COUNT, Column<C>>,
    pub out: Out<Selector>,
    pub ch: UnChangedSelectors<REG_COUNT, Column<C>>,
}

impl<const REG_COUNT: usize, C: ColumnType> TempVarSelectors<REG_COUNT, C> {
    pub fn new<F: FieldExt>(
        meta: &mut ConstraintSystem<F>,
    ) -> TempVarSelectors<REG_COUNT, C>
    where
        ConstraintSystem<F>: NewColumn<C>,
    {
        TempVarSelectors {
            a: SelectiorsA::new_columns(meta),
            b: SelectiorsB::new_columns(meta),
            c: SelectiorsC::new_columns(meta),
            d: SelectiorsD::new_columns(meta),
            out: Out::new(|| meta.selector()),
            ch: UnChangedSelectors::new(|| meta.new_column()),
        }
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

impl<const REG_COUNT: usize> From<trace::Instruction>
    for TempVarSelectorsRow<REG_COUNT>
{
    fn from(inst: trace::Instruction) -> Self {
        let out = Out {
            and: false,
            xor: false,
            or: false,
            sum: false,
            prog: false,
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

        match inst {
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
            // Reference Page 27, Fig. 4
            // trace::Instruction::Add(Add { ri, rj, .. }) => Self {
            //     a: SelectionA::A,
            //     b: SelectionB::Reg(rj),
            //     c: SelectionC::RegN(ri),
            //     d: SelectionD::Zero,
            //     out: Out { sum: true, ..out },
            //     ch: UnChangedSelectors {
            //         regs: ch.regs.set(ri, false),
            //         flag: false,
            //         ..ch
            //     },
            // },
            // Reference Page 34, Fig. 10
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

    Reg(usize),
    RegN(usize),

    A,

    VAddr,
    /// Selects the temporary var associated with this selection vector.
    TempVarA,
}

/// Use `SelectiorsA::new_*` to construct correct selectors.
/// Fields ending with `next` refer to the next row (`t+1).
#[derive(Debug, Clone, Copy)]
pub struct SelectiorsA<const REG_COUNT: usize, C> {
    pub pc_next: C,

    pub reg: [C; REG_COUNT],
    pub reg_next: [C; REG_COUNT],

    pub a: C,

    pub v_addr: C,
    /// Selects the temporary var associated with this selection vector.
    pub temp_var_a: C,
}

impl<const REG_COUNT: usize, C: ColumnType> SelectiorsA<REG_COUNT, Column<C>> {
    fn new_columns<F: FieldExt>(meta: &mut ConstraintSystem<F>) -> Self
    where
        ConstraintSystem<F>: NewColumn<C>,
    {
        SelectiorsA {
            pc_next: meta.new_column(),
            // Do not replace with `[meta.new_column(); REG_COUNT]` it's not equivalent.
            reg: [0; REG_COUNT].map(|_| meta.new_column()),
            reg_next: [0; REG_COUNT].map(|_| meta.new_column()),
            a: meta.new_column(),
            v_addr: meta.new_column(),
            temp_var_a: meta.new_column(),
        }
    }
}

/// Variants ending with `N` refer to the next row (`t+1).
#[derive(Debug, Clone, Copy)]
pub enum SelectionB {
    Pc,
    PcN,

    Reg(RegName),
    RegN(RegName),

    A,
    /// Selects the temporary var associated with this selection vector.
    TempVarB,

    One,
}

/// Use `SelectiorsA::new_*` to construct correct selectors.
/// Fields ending with `next` refer to the next row (`t+1).
#[derive(Debug, Clone, Copy)]
pub struct SelectiorsB<const REG_COUNT: usize, C> {
    pub pc: C,
    pub pc_next: C,

    pub reg: Registers<REG_COUNT, C>,
    pub reg_next: Registers<REG_COUNT, C>,

    pub a: C,

    /// Selects the temporary var associated with this selection vector.
    pub temp_var_b: C,

    pub one: C,
}

impl<const REG_COUNT: usize, C: ColumnType> SelectiorsB<REG_COUNT, Column<C>> {
    fn new_columns<F: FieldExt>(meta: &mut ConstraintSystem<F>) -> Self
    where
        ConstraintSystem<F>: NewColumn<C>,
    {
        SelectiorsB {
            pc: meta.new_column(),
            pc_next: meta.new_column(),
            // Do not replace with `[meta.new_column(); REG_COUNT]` it's not equivalent.
            reg: Registers([0; REG_COUNT].map(|_| meta.new_column())),
            reg_next: Registers([0; REG_COUNT].map(|_| meta.new_column())),
            a: meta.new_column(),
            temp_var_b: meta.new_column(),
            one: meta.new_column(),
        }
    }
}

impl<const REG_COUNT: usize> From<SelectionB> for SelectiorsB<REG_COUNT, bool> {
    fn from(s: SelectionB) -> Self {
        let mut r = SelectiorsB {
            pc: false,
            pc_next: false,
            reg: Registers([false; REG_COUNT]),
            reg_next: Registers([false; REG_COUNT]),
            a: false,
            temp_var_b: false,
            one: false,
        };
        match s {
            SelectionB::Pc => r.pc = true,
            SelectionB::PcN => r.pc_next = true,
            SelectionB::Reg(i) => r.reg[i] = true,
            SelectionB::RegN(i) => r.reg_next[i] = true,
            SelectionB::A => r.a = true,
            SelectionB::TempVarB => r.temp_var_b = true,
            SelectionB::One => r.one = true,
        };
        r
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
pub struct SelectiorsC<const REG_COUNT: usize, C> {
    pub reg: Registers<REG_COUNT, C>,
    pub reg_next: Registers<REG_COUNT, C>,

    pub a: C,

    /// Selects the temporary var associated with this selection vector.
    pub temp_var_c: C,

    pub zero: C,
}

impl<const REG_COUNT: usize, C: ColumnType> SelectiorsC<REG_COUNT, Column<C>> {
    fn new_columns<F: FieldExt>(meta: &mut ConstraintSystem<F>) -> Self
    where
        ConstraintSystem<F>: NewColumn<C>,
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

/// Variants ending with `N` refer to the next row (`t+1).
#[derive(Debug, Clone, Copy)]
pub enum SelectionD {
    Pc,

    Reg(RegName),
    RegN(RegName),

    A,

    /// Selects the temporary var associated with this selection vector.
    TempVarD,

    Zero,
    // No bit is set in this selection vector.
    Unset,
}

/// Use `SelectiorsD::new_*` and From<SelectionD> to construct correct selectors.
/// Fields ending with `next` refer to the next row (`t+1).
#[derive(Debug, Clone, Copy)]
pub struct SelectiorsD<const REG_COUNT: usize, C> {
    pub pc: C,

    pub reg: Registers<REG_COUNT, C>,
    pub reg_next: Registers<REG_COUNT, C>,

    pub a: C,

    /// Selects the temporary var associated with this selection vector.
    pub temp_var_d: C,

    pub zero: C,
}

impl<const REG_COUNT: usize, C: ColumnType> SelectiorsD<REG_COUNT, Column<C>> {
    fn new_columns<F: FieldExt>(meta: &mut ConstraintSystem<F>) -> Self
    where
        ConstraintSystem<F>: NewColumn<C>,
    {
        SelectiorsD {
            // Do not replace with `[meta.new_column(); REG_COUNT]` it's not equivalent.
            pc: meta.new_column(),
            reg: Registers([0; REG_COUNT].map(|_| meta.new_column())),
            reg_next: Registers([0; REG_COUNT].map(|_| meta.new_column())),
            a: meta.new_column(),
            temp_var_d: meta.new_column(),
            zero: meta.new_column(),
        }
    }
}

impl<const REG_COUNT: usize> From<SelectionD> for SelectiorsD<REG_COUNT, bool> {
    fn from(s: SelectionD) -> Self {
        let mut r = SelectiorsD {
            pc: false,
            reg: Registers([false; REG_COUNT]),
            reg_next: Registers([false; REG_COUNT]),
            a: false,
            temp_var_d: false,
            zero: false,
        };
        match s {
            SelectionD::Pc => r.pc = true,
            SelectionD::Reg(i) => r.reg[i] = true,
            SelectionD::RegN(i) => r.reg_next[i] = true,
            SelectionD::A => r.a = true,
            SelectionD::TempVarD => r.temp_var_d = true,
            SelectionD::Zero => r.zero = true,
            SelectionD::Unset => (),
        };
        r
    }
}
