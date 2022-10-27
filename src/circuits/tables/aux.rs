pub mod out;
pub mod out_table;

use core::panic;
use std::fmt::Debug;

use halo2_proofs::arithmetic::FieldExt;

use crate::{
    assign::{AssignCell, NewColumn},
    circuits::{changed::ChangedSelectors, shift},
    instructions::*,
    trace::{self, *},
};

use self::out::{Out, OutPut};

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

#[derive(Debug, Clone, Copy)]
pub struct TempVarSelectors<const REG_COUNT: usize, C: Copy> {
    pub a: SelectorsA<REG_COUNT, C>,
    pub b: SelectorsB<REG_COUNT, C>,
    pub c: SelectorsC<REG_COUNT, C>,
    pub d: SelectorsD<REG_COUNT, C>,
    pub ch: ChangedSelectors<REG_COUNT, C>,
}

impl<const REG_COUNT: usize, C: Copy> TempVarSelectors<REG_COUNT, C> {
    pub fn new<F: FieldExt, M>(meta: &mut M) -> TempVarSelectors<REG_COUNT, C>
    where
        M: NewColumn<C>,
    {
        TempVarSelectors {
            a: SelectorsA::new_columns::<F, M>(meta),
            b: SelectorsB::new_columns::<F, M>(meta),
            c: SelectorsC::new_columns::<F, M>(meta),
            d: SelectorsD::new_columns::<F, M>(meta),
            ch: ChangedSelectors::new(|| meta.new_column()),
        }
    }

    pub fn assign_cells<F: FieldExt, R: AssignCell<F, C>>(
        self,
        region: &mut R,
        offset: usize,
        vals: TempVarSelectorsRow<REG_COUNT>,
    ) where
        C: Debug,
    {
        let Self { a, b, c, d, ch } = self;
        a.assign_cells(region, offset, vals.a.into());
        b.set_cells(region, offset, vals.b.into());
        c.set_cells(region, offset, vals.c.into());
        d.set_cells(region, offset, vals.d.into());
        ch.set_cells(region, offset, vals.ch.convert()).unwrap();
    }

    pub fn map<B: Copy>(
        self,
        mut f: impl FnMut(C) -> B,
    ) -> TempVarSelectors<REG_COUNT, B> {
        let Self { a, b, c, d, ch } = self;
        TempVarSelectors {
            a: a.map(&mut f),
            b: b.map(&mut f),
            c: c.map(&mut f),
            d: d.map(&mut f),
            ch: ch.map(&mut f),
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
    pub ch: ChangedSelectors<REG_COUNT, bool>,
}

impl<const REG_COUNT: usize> From<&Instruction<RegName, ImmediateOrRegName>>
    for TempVarSelectorsRow<REG_COUNT>
{
    fn from(inst: &Instruction<RegName, ImmediateOrRegName>) -> Self {
        let ch = ChangedSelectors {
            regs: Registers([false; REG_COUNT]),
            pc: false,
            flag: false,
        };

        match *inst {
            // Reference Page 27, Fig. 3
            Instruction::And(And { ri, rj, a }) => Self {
                a: SelectionA::A(a),
                b: SelectionB::Reg(rj),
                c: SelectionC::RegN(ri),
                d: SelectionD::Unset,
                out: And::<(), ()>::OUT,
                ch: ChangedSelectors {
                    regs: ch.regs.set(ri, true),
                    flag: true,
                    ..ch
                },
            },
            Instruction::Or(Or { ri, rj, a }) => Self {
                a: SelectionA::A(a),
                b: SelectionB::Reg(rj),
                c: SelectionC::RegN(ri),
                d: SelectionD::Unset,
                out: Or::<(), ()>::OUT,
                ch: ChangedSelectors {
                    regs: ch.regs.set(ri, true),
                    flag: true,
                    ..ch
                },
            },
            Instruction::Xor(Xor { ri, rj, a }) => Self {
                a: SelectionA::A(a),
                b: SelectionB::Reg(rj),
                c: SelectionC::RegN(ri),
                d: SelectionD::Unset,
                out: Xor::<(), ()>::OUT,
                ch: ChangedSelectors {
                    regs: ch.regs.set(ri, true),
                    flag: true,
                    ..ch
                },
            },

            Instruction::Not(Not { ri, a }) => Self {
                a: SelectionA::A(a),
                b: SelectionB::MaxWord,
                c: SelectionC::RegN(ri),
                d: SelectionD::Unset,
                out: Not::<(), ()>::OUT,
                ch: ChangedSelectors {
                    regs: ch.regs.set(ri, true),
                    flag: true,
                    ..ch
                },
            },
            // Reference Page 27, Fig. 4
            Instruction::Add(Add { ri, rj, a }) => Self {
                a: SelectionA::A(a),
                b: SelectionB::Reg(rj),
                c: SelectionC::RegN(ri),
                d: SelectionD::Zero,
                out: Add::<(), ()>::OUT,
                ch: ChangedSelectors {
                    regs: ch.regs.set(ri, true),
                    flag: true,
                    ..ch
                },
            },
            Instruction::Sub(Sub { ri, rj, a }) => Self {
                a: SelectionA::A(a),
                b: SelectionB::RegN(ri),
                c: SelectionC::Reg(rj),
                d: SelectionD::Zero,
                out: Sub::<(), ()>::OUT,
                ch: ChangedSelectors {
                    regs: ch.regs.set(ri, true),
                    flag: true,
                    ..ch
                },
            },
            Instruction::Mull(Mull { ri, rj, a }) => Self {
                a: SelectionA::A(a),
                b: SelectionB::Reg(rj),
                c: SelectionC::NonDet,
                d: SelectionD::RegN(ri),
                out: Mull::<(), ()>::OUT,
                ch: ChangedSelectors {
                    regs: ch.regs.set(ri, true),
                    flag: true,
                    ..ch
                },
            },
            Instruction::UMulh(UMulh { ri, rj, a }) => Self {
                a: SelectionA::A(a),
                b: SelectionB::Reg(rj),
                c: SelectionC::RegN(ri),
                d: SelectionD::NonDet,
                out: UMulh::<(), ()>::OUT,
                ch: ChangedSelectors {
                    regs: ch.regs.set(ri, true),
                    flag: true,
                    ..ch
                },
            },
            Instruction::SMulh(SMulh { ri, rj, a }) => Self {
                a: SelectionA::A(a),
                b: SelectionB::Reg(rj),
                c: SelectionC::RegN(ri),
                d: SelectionD::NonDet,
                out: SMulh::<(), ()>::OUT,
                ch: ChangedSelectors {
                    regs: ch.regs.set(ri, true),
                    flag: true,
                    ..ch
                },
            },
            Instruction::UDiv(UDiv { ri, rj, a }) => Self {
                a: SelectionA::NonDet,
                b: SelectionB::RegN(ri),
                c: SelectionC::A(a),
                d: SelectionD::Reg(rj),
                out: UDiv::<(), ()>::OUT,
                ch: ChangedSelectors {
                    regs: ch.regs.set(ri, true),
                    flag: true,
                    ..ch
                },
            },
            Instruction::UMod(UMod { ri, rj, a }) => Self {
                a: SelectionA::RegN(ri),
                b: SelectionB::NonDet,
                c: SelectionC::A(a),
                d: SelectionD::Reg(rj),
                out: UMod::<(), ()>::OUT,
                ch: ChangedSelectors {
                    regs: ch.regs.set(ri, true),
                    flag: true,
                    ..ch
                },
            },
            Instruction::Shl(Shl { ri, rj, a }) => Self {
                a: SelectionA::A(a),
                b: SelectionB::Reg(rj),
                c: SelectionC::NonDet,
                d: SelectionD::RegN(ri),
                out: Shl::<(), ()>::OUT,
                ch: ChangedSelectors {
                    regs: ch.regs.set(ri, true),
                    flag: true,
                    ..ch
                },
            },
            Instruction::Shr(Shr { ri, rj, a }) => Self {
                a: SelectionA::A(a),
                b: SelectionB::Reg(rj),
                c: SelectionC::RegN(ri),
                d: SelectionD::NonDet,
                out: Shr::<(), ()>::OUT,
                ch: ChangedSelectors {
                    regs: ch.regs.set(ri, true),
                    flag: true,
                    ..ch
                },
            },

            // Reference Page 33, Fig. 8
            Instruction::Cmpe(Cmpe { ri, a }) => Self {
                a: SelectionA::A(a),
                b: SelectionB::Reg(ri),
                c: SelectionC::NonDet,
                d: SelectionD::Unset,
                out: Cmpe::<(), ()>::OUT,
                ch: ChangedSelectors { flag: true, ..ch },
            },
            Instruction::Cmpa(Cmpa { ri, a }) => Self {
                a: SelectionA::Reg(ri),
                b: SelectionB::NonDet,
                c: SelectionC::A(a),
                d: SelectionD::Zero,
                out: Cmpa::<(), ()>::OUT,
                ch: ChangedSelectors { flag: true, ..ch },
            },
            Instruction::Cmpae(Cmpae { ri, a }) => Self {
                a: SelectionA::Reg(ri),
                b: SelectionB::NonDet,
                c: SelectionC::A(a),
                d: SelectionD::One,
                out: Cmpae::<(), ()>::OUT,
                ch: ChangedSelectors { flag: true, ..ch },
            },
            Instruction::Cmpg(Cmpg { ri, a }) => Self {
                a: SelectionA::Reg(ri),
                b: SelectionB::NonDet,
                c: SelectionC::A(a),
                d: SelectionD::Zero,
                out: Cmpg::<(), ()>::OUT,
                ch: ChangedSelectors { flag: true, ..ch },
            },
            Instruction::Cmpge(Cmpge { ri, a }) => Self {
                a: SelectionA::Reg(ri),
                b: SelectionB::NonDet,
                c: SelectionC::A(a),
                d: SelectionD::One,
                out: Cmpge::<(), ()>::OUT,
                ch: ChangedSelectors { flag: true, ..ch },
            },
            Instruction::Mov(Mov { ri, a }) => Self {
                a: SelectionA::A(a),
                b: SelectionB::RegN(ri),
                c: SelectionC::Zero,
                d: SelectionD::Unset,
                out: Mov::<(), ()>::OUT,
                ch: ChangedSelectors {
                    regs: ch.regs.set(ri, true),
                    ..ch
                },
            },
            Instruction::CMov(CMov { ri, a }) => Self {
                a: SelectionA::RegN(ri),
                b: SelectionB::A(a),
                c: SelectionC::Zero,
                // The table on page 34 call for rj,t.
                // It's a typo, on page 33 d = ri,t.
                d: SelectionD::Reg(ri),
                out: CMov::<(), ()>::OUT,
                ch: ChangedSelectors {
                    regs: ch.regs.set(ri, true),
                    ..ch
                },
            },
            Instruction::Jmp(Jmp { a }) => Self {
                a: SelectionA::A(a),
                b: SelectionB::PcN,
                c: SelectionC::Zero,
                d: SelectionD::Unset,
                out: Jmp::<()>::OUT,
                ch: ChangedSelectors { pc: true, ..ch },
            },
            Instruction::CJmp(CJmp { a }) => Self {
                a: SelectionA::PcN,
                b: SelectionB::A(a),
                c: SelectionC::Zero,
                d: SelectionD::PcPlusOne,
                out: CJmp::<()>::OUT,
                ch: ChangedSelectors { pc: true, ..ch },
            },
            Instruction::CnJmp(CnJmp { a }) => Self {
                a: SelectionA::PcN,
                b: SelectionB::PcPlusOne,
                c: SelectionC::Zero,
                d: SelectionD::A(a),
                out: CnJmp::<()>::OUT,
                ch: ChangedSelectors { pc: true, ..ch },
            },

            Instruction::LoadW(LoadW { ri, .. }) => Self {
                a: SelectionA::VAddr,
                b: SelectionB::Reg(ri),
                c: SelectionC::Zero,
                d: SelectionD::Zero,
                out: LoadW::<(), ()>::OUT,
                ch: ChangedSelectors {
                    regs: ch.regs.set(ri, true),
                    ..ch
                },
            },
            Instruction::StoreW(StoreW { ri, .. }) => Self {
                a: SelectionA::VAddr,
                b: SelectionB::RegN(ri),
                c: SelectionC::Zero,
                d: SelectionD::Zero,
                out: StoreW::<(), ()>::OUT,
                ch,
            },

            // Answer's selection vectors, except `a`, are undefined.
            // Reference page 35
            Instruction::Answer(Answer { a }) => Self {
                a: SelectionA::A(a),
                b: SelectionB::Pc,
                c: SelectionC::Zero,
                d: SelectionD::Zero,
                out: Answer::<()>::OUT,
                ch,
            },
        }
    }
}

impl<const REG_COUNT: usize> TempVarSelectorsRow<REG_COUNT> {
    pub fn push_temp_var_vals<F: FieldExt, const WORD_BITS: u32>(
        &self,
        steps: &[Step<REG_COUNT>],
        i: usize,
    ) -> (u32, u32, F, F) {
        let pc = || steps[i].pc.0;
        let pc_n = || steps[i + 1].pc.0;
        let reg = |r| steps[i].regs[r].0;
        let reg_n = |r| steps[i + 1].regs[r].0;
        let a = |ior| {
            let iors = steps[i].instruction.a();
            // Double check
            assert_eq!(iors, ior);
            match ior {
                ImmediateOrRegName::Immediate(a) => a.0,
                ImmediateOrRegName::RegName(r) => r.0.into(),
            }
        };
        let v_addr = || steps[i].v_addr.unwrap().0;

        let ta = match self.a {
            SelectionA::PcN => pc_n(),
            SelectionA::Reg(r) => reg(r),
            SelectionA::RegN(r) => reg_n(r),
            SelectionA::A(ior) => a(ior),
            SelectionA::VAddr => v_addr(),
            SelectionA::NonDet => match steps[i].instruction {
                Instruction::UDiv(UDiv { rj, a, .. }) => {
                    let a = a.get(&steps[i].regs).0;
                    if a == 0 {
                        0
                    } else {
                        steps[i].regs[rj].0 % a
                    }
                }
                _ => panic!("Unhandled non-deterministic advice"),
            },
        };

        let tb = match self.b {
            SelectionB::Pc => pc(),
            SelectionB::PcN => pc_n(),
            SelectionB::PcPlusOne => pc() + 1,
            SelectionB::Reg(r) => reg(r),
            SelectionB::RegN(r) => reg_n(r),
            SelectionB::A(ior) => a(ior),
            SelectionB::NonDet => match steps[i].instruction {
                Instruction::UMod(UMod { rj, a, .. }) => {
                    let a = a.get(&steps[i].regs).0;
                    if a == 0 {
                        0
                    } else {
                        steps[i].regs[rj].0 / a
                    }
                }
                Instruction::Cmpa(Cmpa { ri, a: ior }) => {
                    let ta = steps[i].regs[ri].0 as u64;
                    let tc = a(ior) as u64;
                    // td is 0

                    // See page 32
                    (if ta > tc {
                        2u64.pow(WORD_BITS) - (ta - tc)
                    } else {
                        tc - ta
                    }) as u32
                }
                Instruction::Cmpg(Cmpg { ri, a: ior }) => {
                    let ta = steps[i].regs[ri].0 as u64;
                    let tc = a(ior) as u64;
                    // td is 0

                    (if ta > tc {
                        2u64.pow(WORD_BITS) - (ta - tc)
                    } else {
                        tc - ta
                    }) as u32
                }
                Instruction::Cmpae(Cmpae { ri, a: ior }) => {
                    let ta = steps[i].regs[ri].0 as u64;
                    let tc = a(ior) as u64;
                    // td is 1

                    (if ta >= tc {
                        2u64.pow(WORD_BITS) - 1 - (ta - tc)
                    } else {
                        tc - ta - 1
                    }) as u32
                }
                Instruction::Cmpge(Cmpge { ri, a: ior }) => {
                    let ta = steps[i].regs[ri].0 as u64;
                    let tc = a(ior) as u64;
                    // td is 1

                    (if ta >= tc {
                        2u64.pow(WORD_BITS) - 1 - (ta - tc)
                    } else {
                        tc - ta - 1
                    }) as u32
                }
                _ => panic!("Unhandled non-deterministic advice"),
            },
            SelectionB::MaxWord => (2u64.pow(WORD_BITS) - 1) as u32,
        };

        let tc = match self.c {
            SelectionC::Reg(r) => F::from(reg(r) as u64),
            SelectionC::RegN(r) => F::from(reg_n(r) as u64),
            SelectionC::A(ior) => F::from(a(ior) as u64),
            SelectionC::NonDet => match steps[i].instruction {
                Instruction::Mull(Mull { rj, a, .. }) => {
                    let r = steps[i].regs[rj].0 as u128
                        * a.get(&steps[i].regs).0 as u128;
                    // c is the upper word, and d is the lower word of multiplication (page 28)
                    F::from(trace::truncate::<WORD_BITS>(r >> WORD_BITS).0 as u64)
                }
                Instruction::Cmpe(Cmpe { ri, a, .. }) => {
                    let c = steps[i].regs[ri].0 ^ a.get(&steps[i].regs).0;
                    // c is the bit wise XOR of ri, and a.
                    F::from(c as u64)
                }
                Instruction::Shl(Shl { rj, a, ri }) => {
                    let a = a.get(&steps[i].regs).0;
                    let b = steps[i].regs[rj].0;
                    let d = truncate::<WORD_BITS>((b as u128) << (a as u128));
                    assert_eq!(d, steps[i + 1].regs[ri]);

                    shift::non_det_c::<WORD_BITS, F>(a.into(), b.into(), d.0.into())
                }
                _ => panic!("Unhandled non-deterministic advice"),
            },
            SelectionC::Zero => F::zero(),
        };

        let td = match self.d {
            SelectionD::PcPlusOne => F::from((pc() + 1) as u64),
            SelectionD::Reg(r) => F::from(reg(r) as u64),
            SelectionD::RegN(r) => F::from(reg_n(r) as u64),
            SelectionD::A(ior) => F::from(a(ior) as u64),
            SelectionD::NonDet => match steps[i].instruction {
                Instruction::UMulh(UMulh { rj, a, .. }) => {
                    let r = steps[i].regs[rj].0 as u128
                        * a.get(&steps[i].regs).0 as u128;
                    F::from(trace::truncate::<WORD_BITS>(r).0 as u64)
                }
                Instruction::SMulh(SMulh { rj, a, .. }) => {
                    let a = a.get(&steps[i].regs);
                    let rj = steps[i].regs[rj];

                    let (_upper, lower, _flag) = SMulh::eval::<WORD_BITS>(a, rj);
                    F::from(lower.0 as u64)
                }
                Instruction::Shr(Shr { ri, rj, a }) => {
                    let a = a.get(&steps[i].regs);
                    let b = steps[i].regs[rj];
                    let c = b.0 >> a.0;
                    assert_eq!(c, steps[i + 1].regs[ri].0);

                    dbg!(shift::non_det_d::<WORD_BITS, F>(
                        a.into(),
                        b.into(),
                        c.into()
                    ))
                }
                _ => panic!("Unhandled non-deterministic advice"),
            },
            SelectionD::Zero => F::zero(),
            SelectionD::One => F::one(),
            SelectionD::Unset => F::zero(),
        };
        (ta, tb, tc, td)
    }
}

/// Variants ending with `N` refer to the next row (`t+1).
#[derive(Debug, Clone, Copy)]
pub enum SelectionA {
    PcN,

    Reg(RegName),
    RegN(RegName),

    A(ImmediateOrRegName),

    VAddr,
    /// "non-deterministic advice"
    NonDet,
}

/// Use `SelectorsA::new_*` to construct correct selectors.
/// Fields ending with `next` refer to the next row (`t+1).
#[derive(Debug, Clone, Copy)]
pub struct SelectorsA<const REG_COUNT: usize, C: Copy> {
    pub pc_next: C,

    pub reg: Registers<REG_COUNT, C>,
    pub reg_next: Registers<REG_COUNT, C>,

    pub a: C,

    pub v_addr: C,
    /// "non-deterministic advice"
    pub non_det: C,
}

impl<const REG_COUNT: usize> From<SelectionA> for SelectorsA<REG_COUNT, bool> {
    fn from(s: SelectionA) -> Self {
        let mut r = SelectorsA {
            pc_next: false,
            reg: Registers([false; REG_COUNT]),
            reg_next: Registers([false; REG_COUNT]),
            a: false,
            v_addr: false,
            non_det: false,
        };
        match s {
            SelectionA::Reg(i) => r.reg[i] = true,
            SelectionA::RegN(i) => r.reg_next[i] = true,
            SelectionA::A(ImmediateOrRegName::Immediate(_)) => r.a = true,
            SelectionA::A(ImmediateOrRegName::RegName(i)) => r.reg[i] = true,
            SelectionA::NonDet => r.non_det = true,
            SelectionA::PcN => r.pc_next = true,
            SelectionA::VAddr => r.v_addr = true,
        };
        r
    }
}

impl<const REG_COUNT: usize, C: Copy> SelectorsA<REG_COUNT, C> {
    fn new_columns<F: FieldExt, M>(meta: &mut M) -> Self
    where
        M: NewColumn<C>,
    {
        SelectorsA {
            pc_next: meta.new_column(),
            // Do not replace with `[meta.new_column(); REG_COUNT]` it's not equivalent.
            reg: [0; REG_COUNT].map(|_| meta.new_column()).into(),
            reg_next: [0; REG_COUNT].map(|_| meta.new_column()).into(),
            a: meta.new_column(),
            v_addr: meta.new_column(),
            non_det: meta.new_column(),
        }
    }

    pub fn map<B: Copy>(
        self,
        mut f: impl FnMut(C) -> B,
    ) -> SelectorsA<REG_COUNT, B> {
        let Self {
            pc_next,
            reg,
            reg_next,
            a,
            v_addr,
            non_det,
        } = self;
        SelectorsA {
            pc_next: f(pc_next),
            reg: reg.map(&mut f),
            reg_next: reg_next.map(&mut f),
            a: f(a),
            v_addr: f(v_addr),
            non_det: f(non_det),
        }
    }
}

impl<const REG_COUNT: usize, C: Copy> SelectorsA<REG_COUNT, C> {
    fn assign_cells<F: FieldExt, R: AssignCell<F, C>>(
        self,
        region: &mut R,
        offset: usize,
        vals: SelectorsA<REG_COUNT, bool>,
    ) {
        let Self {
            pc_next,
            reg,
            reg_next,
            a,
            v_addr,
            non_det: temp_var_a,
        } = self;

        region
            .assign_cell(pc_next, offset, vals.pc_next.into())
            .unwrap();

        for (rc, rv) in reg.0.into_iter().zip(vals.reg.0.into_iter()) {
            region.assign_cell(rc, offset, rv.into()).unwrap();
        }
        for (rc, rv) in reg_next.0.into_iter().zip(vals.reg_next.0.into_iter()) {
            region.assign_cell(rc, offset, rv.into()).unwrap();
        }

        region.assign_cell(a, offset, vals.a.into()).unwrap();
        region
            .assign_cell(v_addr, offset, vals.v_addr.into())
            .unwrap();
        region
            .assign_cell(temp_var_a, offset, vals.non_det.into())
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

    A(ImmediateOrRegName),
    /// Selects the temporary var associated with this selection vector.
    NonDet,

    /// 2^W − 1
    MaxWord,
}

/// Use `SelectorsA::new_*` to construct correct selectors.
/// Fields ending with `next` refer to the next row (`t+1).
#[derive(Debug, Clone, Copy)]
pub struct SelectorsB<const REG_COUNT: usize, C: Copy> {
    pub pc: C,
    pub pc_next: C,

    pub pc_plus_one: C,

    pub reg: Registers<REG_COUNT, C>,
    pub reg_next: Registers<REG_COUNT, C>,

    pub a: C,

    /// "non-deterministic advice"
    pub non_det: C,

    pub max_word: C,
}

impl<const REG_COUNT: usize, C: Copy> SelectorsB<REG_COUNT, C> {
    fn new_columns<F: FieldExt, M>(meta: &mut M) -> Self
    where
        M: NewColumn<C>,
    {
        SelectorsB {
            pc: meta.new_column(),
            pc_next: meta.new_column(),
            pc_plus_one: meta.new_column(),
            // Do not replace with `[meta.new_column(); REG_COUNT]` it's not equivalent.
            reg: Registers([0; REG_COUNT].map(|_| meta.new_column())),
            reg_next: Registers([0; REG_COUNT].map(|_| meta.new_column())),
            a: meta.new_column(),
            non_det: meta.new_column(),
            max_word: meta.new_column(),
        }
    }

    pub fn map<B: Copy>(
        self,
        mut f: impl FnMut(C) -> B,
    ) -> SelectorsB<REG_COUNT, B> {
        let Self {
            pc,
            pc_next,
            pc_plus_one,
            reg,
            reg_next,
            a,
            non_det,
            max_word,
        } = self;

        SelectorsB {
            pc: f(pc),
            pc_next: f(pc_next),
            pc_plus_one: f(pc_plus_one),
            reg: reg.map(&mut f),
            reg_next: reg_next.map(&mut f),
            a: f(a),
            non_det: f(non_det),
            max_word: f(max_word),
        }
    }
}

impl<const REG_COUNT: usize> From<SelectionB> for SelectorsB<REG_COUNT, bool> {
    fn from(s: SelectionB) -> Self {
        let mut r = SelectorsB {
            pc: false,
            pc_next: false,
            pc_plus_one: false,
            reg: Registers([false; REG_COUNT]),
            reg_next: Registers([false; REG_COUNT]),
            a: false,
            non_det: false,
            max_word: false,
        };
        match s {
            SelectionB::Pc => r.pc = true,
            SelectionB::PcN => r.pc_next = true,
            SelectionB::PcPlusOne => r.pc_plus_one = true,
            SelectionB::Reg(i) => r.reg[i] = true,
            SelectionB::RegN(i) => r.reg_next[i] = true,
            SelectionB::A(ImmediateOrRegName::Immediate(_)) => r.a = true,
            SelectionB::A(ImmediateOrRegName::RegName(i)) => r.reg[i] = true,
            SelectionB::NonDet => r.non_det = true,
            SelectionB::MaxWord => r.max_word = true,
        };
        r
    }
}

impl<const REG_COUNT: usize, C: Copy> SelectorsB<REG_COUNT, C> {
    fn set_cells<F: FieldExt, R: AssignCell<F, C>>(
        self,
        region: &mut R,
        offset: usize,
        vals: SelectorsB<REG_COUNT, bool>,
    ) {
        let Self {
            pc,
            pc_next,
            pc_plus_one,
            reg,
            reg_next,
            a,
            non_det,
            max_word,
        } = self;

        region.assign_cell(pc, offset, vals.pc.into()).unwrap();
        region
            .assign_cell(pc_next, offset, vals.pc_next.into())
            .unwrap();
        region
            .assign_cell(pc_plus_one, offset, vals.pc_plus_one.into())
            .unwrap();

        for (rc, rv) in reg.0.into_iter().zip(vals.reg.0.into_iter()) {
            region.assign_cell(rc, offset, rv.into()).unwrap();
        }
        for (rc, rv) in reg_next.0.into_iter().zip(vals.reg_next.0.into_iter()) {
            region.assign_cell(rc, offset, rv.into()).unwrap();
        }

        region.assign_cell(a, offset, vals.a.into()).unwrap();
        region
            .assign_cell(max_word, offset, vals.max_word.into())
            .unwrap();
        region
            .assign_cell(non_det, offset, vals.non_det.into())
            .unwrap();
    }
}

/// Variants ending with `N` refer to the next row (`t+1).
#[derive(Debug, Clone, Copy)]
pub enum SelectionC {
    Reg(RegName),
    RegN(RegName),

    A(ImmediateOrRegName),

    /// "non-deterministic advice"
    NonDet,
    Zero,
}

/// Use `SelectorsA::new_*` to construct correct selectors.
/// Fields ending with `next` refer to the next row (`t+1).
#[derive(Debug, Clone, Copy)]
pub struct SelectorsC<const REG_COUNT: usize, C: Copy> {
    pub reg: Registers<REG_COUNT, C>,
    pub reg_next: Registers<REG_COUNT, C>,

    pub a: C,

    /// "non-deterministic advice"
    pub non_det: C,

    pub zero: C,
}

impl<const REG_COUNT: usize, C: Copy> SelectorsC<REG_COUNT, C> {
    fn new_columns<F: FieldExt, M>(meta: &mut M) -> Self
    where
        M: NewColumn<C>,
    {
        SelectorsC {
            // Do not replace with `[meta.new_column(); REG_COUNT]` it's not equivalent.
            reg: Registers([0; REG_COUNT].map(|_| meta.new_column())),
            reg_next: Registers([0; REG_COUNT].map(|_| meta.new_column())),
            a: meta.new_column(),
            non_det: meta.new_column(),
            zero: meta.new_column(),
        }
    }

    pub fn map<B: Copy>(
        self,
        mut f: impl FnMut(C) -> B,
    ) -> SelectorsC<REG_COUNT, B> {
        let Self {
            reg,
            reg_next,
            a,
            non_det,
            zero,
        } = self;

        SelectorsC {
            reg: reg.map(&mut f),
            reg_next: reg_next.map(&mut f),
            a: f(a),
            non_det: f(non_det),
            zero: f(zero),
        }
    }
}

impl<const REG_COUNT: usize> From<SelectionC> for SelectorsC<REG_COUNT, bool> {
    fn from(s: SelectionC) -> Self {
        let mut r = SelectorsC {
            reg: Registers([false; REG_COUNT]),
            reg_next: Registers([false; REG_COUNT]),
            a: false,
            non_det: false,
            zero: false,
        };
        match s {
            SelectionC::Reg(i) => r.reg[i] = true,
            SelectionC::RegN(i) => r.reg_next[i] = true,
            SelectionC::A(ImmediateOrRegName::Immediate(_)) => r.a = true,
            SelectionC::A(ImmediateOrRegName::RegName(i)) => r.reg[i] = true,
            SelectionC::NonDet => r.non_det = true,
            SelectionC::Zero => r.zero = true,
        };
        r
    }
}

impl<const REG_COUNT: usize, C: Copy> SelectorsC<REG_COUNT, C> {
    fn set_cells<F: FieldExt, R: AssignCell<F, C>>(
        self,
        region: &mut R,
        offset: usize,
        vals: SelectorsC<REG_COUNT, bool>,
    ) {
        let Self {
            reg,
            reg_next,
            a,
            non_det,
            zero,
        } = self;

        for (rc, rv) in reg.0.into_iter().zip(vals.reg.0.into_iter()) {
            region.assign_cell(rc, offset, rv.into()).unwrap();
        }
        for (rc, rv) in reg_next.0.into_iter().zip(vals.reg_next.0.into_iter()) {
            region.assign_cell(rc, offset, rv.into()).unwrap();
        }

        region.assign_cell(a, offset, vals.a.into()).unwrap();
        region.assign_cell(zero, offset, vals.zero.into()).unwrap();
        region
            .assign_cell(non_det, offset, vals.non_det.into())
            .unwrap();
    }
}

/// Variants ending with `N` refer to the next row (`t+1).
#[derive(Debug, Clone, Copy)]
pub enum SelectionD {
    PcPlusOne,

    Reg(RegName),
    RegN(RegName),

    A(ImmediateOrRegName),

    /// "non-deterministic advice"
    NonDet,

    Zero,
    One,
    /// No bit is set in this selection vector.
    /// Denoted `/` in the arya paper.
    /// This can likly be merged with `Zero`.
    Unset,
}

/// Use `SelectorsD::new_*` and From<SelectionD> to construct correct selectors.
/// Fields ending with `next` refer to the next row (`t+1).
#[derive(Debug, Clone, Copy)]
pub struct SelectorsD<const REG_COUNT: usize, C: Copy> {
    pub pc: C,

    pub reg: Registers<REG_COUNT, C>,
    pub reg_next: Registers<REG_COUNT, C>,

    pub a: C,

    /// "non-deterministic advice"
    pub non_det: C,

    pub zero: C,
    pub one: C,
}

impl<const REG_COUNT: usize, C: Copy> SelectorsD<REG_COUNT, C> {
    fn new_columns<F: FieldExt, M>(meta: &mut M) -> Self
    where
        M: NewColumn<C>,
    {
        SelectorsD {
            // Do not replace with `[meta.new_column(); REG_COUNT]` it's not equivalent.
            pc: meta.new_column(),

            reg: Registers([0; REG_COUNT].map(|_| meta.new_column())),
            reg_next: Registers([0; REG_COUNT].map(|_| meta.new_column())),
            a: meta.new_column(),
            non_det: meta.new_column(),
            zero: meta.new_column(),
            one: meta.new_column(),
        }
    }

    pub fn map<B: Copy>(
        self,
        mut f: impl FnMut(C) -> B,
    ) -> SelectorsD<REG_COUNT, B> {
        let Self {
            pc,
            reg,
            reg_next,
            a,
            non_det,
            zero,
            one,
        } = self;

        SelectorsD {
            pc: f(pc),
            reg: reg.map(&mut f),
            reg_next: reg_next.map(&mut f),
            a: f(a),
            non_det: f(non_det),
            zero: f(zero),
            one: f(one),
        }
    }
}

impl<const REG_COUNT: usize> From<SelectionD> for SelectorsD<REG_COUNT, bool> {
    fn from(s: SelectionD) -> Self {
        let mut r = SelectorsD {
            pc: false,
            reg: Registers([false; REG_COUNT]),
            reg_next: Registers([false; REG_COUNT]),
            a: false,
            non_det: false,
            zero: false,
            one: false,
        };
        match s {
            SelectionD::PcPlusOne => {
                r.pc = true;
                r.one = true;
            }
            SelectionD::Reg(i) => r.reg[i] = true,
            SelectionD::RegN(i) => r.reg_next[i] = true,
            SelectionD::A(ImmediateOrRegName::Immediate(_)) => r.a = true,
            SelectionD::A(ImmediateOrRegName::RegName(i)) => r.reg[i] = true,
            SelectionD::NonDet => r.non_det = true,
            SelectionD::Zero => r.zero = true,
            SelectionD::One => r.one = true,
            SelectionD::Unset => (),
        };
        r
    }
}

impl<const REG_COUNT: usize, C: Copy> SelectorsD<REG_COUNT, C> {
    fn set_cells<F: FieldExt, R: AssignCell<F, C>>(
        self,
        region: &mut R,
        offset: usize,
        vals: SelectorsD<REG_COUNT, bool>,
    ) {
        let Self {
            pc,
            reg,
            reg_next,
            a,
            non_det,
            zero,
            one,
        } = self;

        region.assign_cell(pc, offset, vals.pc.into()).unwrap();
        for (rc, rv) in reg.0.into_iter().zip(vals.reg.0.into_iter()) {
            region.assign_cell(rc, offset, rv.into()).unwrap();
        }
        for (rc, rv) in reg_next.0.into_iter().zip(vals.reg_next.0.into_iter()) {
            region.assign_cell(rc, offset, rv.into()).unwrap();
        }

        region.assign_cell(a, offset, vals.a.into()).unwrap();
        region.assign_cell(zero, offset, vals.zero.into()).unwrap();
        region.assign_cell(one, offset, vals.one.into()).unwrap();
        region
            .assign_cell(non_det, offset, vals.non_det.into())
            .unwrap();
    }
}
