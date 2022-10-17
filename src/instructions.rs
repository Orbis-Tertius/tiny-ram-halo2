use std::fmt::Display;

use crate::trace::{truncate, ImmediateOrRegName, RegName, Word};

pub mod opcode;

/// Docs for a variant are on each variant's struct,
/// They can also be found on page 9 of the TinyRAM Architecture Specification v2.000.
#[derive(Debug, Clone, Copy)]
pub enum Instruction<R, A> {
    And(And<R, A>),
    Or(Or<R, A>),
    Xor(Xor<R, A>),
    Not(Not<R, A>),
    Add(Add<R, A>),
    Sub(Sub<R, A>),
    Mull(Mull<R, A>),
    UMulh(UMulh<R, A>),
    SMulh(SMulh<R, A>),
    UDiv(UDiv<R, A>),
    UMod(UMod<R, A>),
    Shl(Shl<R, A>),
    Shr(Shr<R, A>),
    /// compare equal
    Cmpe(Cmpe<R, A>),
    /// compare above, unsigned
    Cmpa(Cmpa<R, A>),
    /// compare above or equal, unsigned
    Cmpae(Cmpae<R, A>),
    // compare greater signed
    Cmpg(Cmpg<R, A>),
    /// compare greater or equal, signed
    Cmpge(Cmpge<R, A>),
    Mov(Mov<R, A>),
    CMov(CMov<R, A>),
    Jmp(Jmp<A>),
    CJmp(CJmp<A>),
    CnJmp(CnJmp<A>),
    StoreW(StoreW<R, A>),
    LoadW(LoadW<R, A>),
    Answer(Answer<A>),
}

impl<R, A> Instruction<R, A> {
    pub fn name(&self) -> &str {
        match self {
            Instruction::And(_) => "And",
            Instruction::LoadW(_) => "Load.w",
            Instruction::StoreW(_) => "Store.w",
            Instruction::Answer(_) => "Answer",
            Instruction::Or(_) => "Or",
            Instruction::Xor(_) => "Xor",
            Instruction::Not(_) => "Not",
            Instruction::Add(_) => "Add",
            Instruction::Sub(_) => "Sub",
            Instruction::Mull(_) => "Mull",
            Instruction::UMulh(_) => "UMulh",
            Instruction::SMulh(_) => "SMulh",
            Instruction::UDiv(_) => "Udiv",
            Instruction::UMod(_) => "UMod",
            Instruction::Shl(_) => "Shl",
            Instruction::Shr(_) => "Shr",
            Instruction::Cmpe(_) => "Cmpe",
            Instruction::Cmpa(_) => "Cmpa",
            Instruction::Cmpae(_) => "Cmpae",
            Instruction::Cmpg(_) => "Cmpg",
            Instruction::Cmpge(_) => "Cmpge",
            Instruction::Mov(_) => "Mov",
            Instruction::CMov(_) => "Cmov",
            Instruction::Jmp(_) => "Jmp",
            Instruction::CJmp(_) => "CJmp",
            Instruction::CnJmp(_) => "CnJmp",
        }
    }

    /// See TinyRAM 2.0 spec (page 16)
    /// The op code is the first field (`#1` in the table) of the binary instruction encoding.
    pub fn opcode(&self) -> u128 {
        match self {
            Instruction::And(_) => 0b00000,
            Instruction::Or(_) => 0b00001,
            Instruction::Xor(_) => 0b00010,
            Instruction::Not(_) => 0b00011,
            Instruction::Add(_) => 0b00100,
            Instruction::Sub(_) => 0b00101,
            Instruction::Mull(_) => 0b00110,
            Instruction::UMulh(_) => 0b00111,
            Instruction::SMulh(_) => 0b01000,
            Instruction::UDiv(_) => 0b01001,
            Instruction::UMod(_) => 0b01010,
            Instruction::Shl(_) => 0b01011,
            Instruction::Shr(_) => 0b01100,
            Instruction::Cmpe(_) => 0b01101,
            Instruction::Cmpa(_) => 0b01110,
            Instruction::Cmpae(_) => 0b01111,
            Instruction::Cmpg(_) => 0b10000,
            Instruction::Cmpge(_) => 0b10001,
            Instruction::Mov(_) => 0b10010,
            Instruction::CMov(_) => 0b10011,
            Instruction::Jmp(_) => 0b10100,
            Instruction::CJmp(_) => 0b10101,
            Instruction::CnJmp(_) => 0b10110,
            Instruction::StoreW(_) => 0b11100,
            Instruction::LoadW(_) => 0b11101,
            Instruction::Answer(_) => 0b11111,
        }
    }

    pub fn is_store(&self) -> bool {
        matches!(self, Instruction::StoreW(_))
    }

    pub fn is_load(&self) -> bool {
        matches!(self, Instruction::LoadW(_))
    }
}

impl Instruction<RegName, ImmediateOrRegName> {
    pub fn ri(&self) -> Option<RegName> {
        match self {
            Instruction::And(And { ri, .. })
            | Instruction::LoadW(LoadW { ri, .. })
            | Instruction::StoreW(StoreW { ri, .. })
            | Instruction::Or(Or { ri, .. })
            | Instruction::Xor(Xor { ri, .. })
            | Instruction::Not(Not { ri, .. })
            | Instruction::Add(Add { ri, .. })
            | Instruction::Sub(Sub { ri, .. })
            | Instruction::Mull(Mull { ri, .. })
            | Instruction::UMulh(UMulh { ri, .. })
            | Instruction::SMulh(SMulh { ri, .. })
            | Instruction::UDiv(UDiv { ri, .. })
            | Instruction::UMod(UMod { ri, .. })
            | Instruction::Shl(Shl { ri, .. })
            | Instruction::Shr(Shr { ri, .. })
            | Instruction::Cmpe(Cmpe { ri, .. })
            | Instruction::Cmpa(Cmpa { ri, .. })
            | Instruction::Cmpae(Cmpae { ri, .. })
            | Instruction::Cmpg(Cmpg { ri, .. })
            | Instruction::Cmpge(Cmpge { ri, .. })
            | Instruction::Mov(Mov { ri, .. })
            | Instruction::CMov(CMov { ri, .. }) => Some(*ri),
            Instruction::Answer(_)
            | Instruction::Jmp(_)
            | Instruction::CJmp(_)
            | Instruction::CnJmp(_) => None,
        }
    }

    pub fn rj(&self) -> Option<RegName> {
        match self {
            Instruction::And(And { rj, .. })
            | Instruction::Or(Or { rj, .. })
            | Instruction::Xor(Xor { rj, .. })
            | Instruction::Add(Add { rj, .. })
            | Instruction::Sub(Sub { rj, .. })
            | Instruction::Mull(Mull { rj, .. })
            | Instruction::UMulh(UMulh { rj, .. })
            | Instruction::SMulh(SMulh { rj, .. })
            | Instruction::UDiv(UDiv { rj, .. })
            | Instruction::UMod(UMod { rj, .. })
            | Instruction::Shl(Shl { rj, .. })
            | Instruction::Shr(Shr { rj, .. }) => Some(*rj),
            Instruction::Answer(_)
            | Instruction::Cmpe(_)
            | Instruction::Cmpa(_)
            | Instruction::Cmpae(_)
            | Instruction::Cmpg(_)
            | Instruction::Cmpge(_)
            | Instruction::Mov(_)
            | Instruction::CMov(_)
            | Instruction::Jmp(_)
            | Instruction::CJmp(_)
            | Instruction::CnJmp(_)
            | Instruction::Not(_)
            | Instruction::StoreW(_)
            | Instruction::LoadW(_) => None,
        }
    }

    pub fn a(&self) -> ImmediateOrRegName {
        match self {
            Instruction::And(And { a, .. })
            | Instruction::LoadW(LoadW { a, .. })
            | Instruction::StoreW(StoreW { a, .. })
            | Instruction::Or(Or { a, .. })
            | Instruction::Xor(Xor { a, .. })
            | Instruction::Not(Not { a, .. })
            | Instruction::Add(Add { a, .. })
            | Instruction::Sub(Sub { a, .. })
            | Instruction::Mull(Mull { a, .. })
            | Instruction::UMulh(UMulh { a, .. })
            | Instruction::SMulh(SMulh { a, .. })
            | Instruction::UDiv(UDiv { a, .. })
            | Instruction::UMod(UMod { a, .. })
            | Instruction::Shl(Shl { a, .. })
            | Instruction::Shr(Shr { a, .. })
            | Instruction::Cmpe(Cmpe { a, .. })
            | Instruction::Cmpa(Cmpa { a, .. })
            | Instruction::Cmpae(Cmpae { a, .. })
            | Instruction::Cmpg(Cmpg { a, .. })
            | Instruction::Cmpge(Cmpge { a, .. })
            | Instruction::Mov(Mov { a, .. })
            | Instruction::CMov(CMov { a, .. })
            | Instruction::Jmp(Jmp { a, .. })
            | Instruction::CJmp(CJmp { a, .. })
            | Instruction::CnJmp(CnJmp { a, .. })
            | Instruction::Answer(Answer { a }) => *a,
        }
    }
}

impl Display for Instruction<RegName, ImmediateOrRegName> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ", self.name())?;
        match self {
            Instruction::And(And { ri, rj, a })
            | Instruction::Or(Or { ri, rj, a })
            | Instruction::Xor(Xor { ri, rj, a })
            | Instruction::Add(Add { ri, rj, a })
            | Instruction::Sub(Sub { ri, rj, a })
            | Instruction::Mull(Mull { ri, rj, a })
            | Instruction::UMulh(UMulh { ri, rj, a })
            | Instruction::SMulh(SMulh { ri, rj, a })
            | Instruction::UDiv(UDiv { ri, rj, a })
            | Instruction::UMod(UMod { ri, rj, a })
            | Instruction::Shl(Shl { ri, rj, a })
            | Instruction::Shr(Shr { ri, rj, a }) => {
                write!(f, "r{} ", ri.0)?;
                write!(f, "r{} ", rj.0)?;
                write!(f, "{}", a)
            }
            Instruction::Not(Not { ri, a })
            | Instruction::Cmpe(Cmpe { ri, a })
            | Instruction::Cmpa(Cmpa { ri, a })
            | Instruction::Cmpae(Cmpae { ri, a })
            | Instruction::Cmpg(Cmpg { ri, a })
            | Instruction::Cmpge(Cmpge { ri, a })
            | Instruction::Mov(Mov { ri, a })
            | Instruction::CMov(CMov { ri, a })
            | Instruction::LoadW(LoadW { ri, a })
            | Instruction::StoreW(StoreW { ri, a }) => {
                write!(f, "r{} ", ri.0)?;
                write!(f, "{}", a)
            }

            Instruction::Jmp(Jmp { a })
            | Instruction::CJmp(CJmp { a })
            | Instruction::CnJmp(CnJmp { a })
            | Instruction::Answer(Answer { a }) => write!(f, "{}", a),
        }
    }
}

/// compute bitwise AND of `[rj]` and `[A]` and store result in ri
#[derive(Debug, Clone, Copy)]
pub struct And<R, A> {
    pub ri: R,
    pub rj: R,
    pub a: A,
}

/// compute bitwise OR of `[rj]` and `[A]` and store result in ri
#[derive(Debug, Clone, Copy)]
pub struct Or<R, A> {
    pub ri: R,
    pub rj: R,
    pub a: A,
}

/// compute bitwise OR of `[rj]` and `[A]` and store result in ri
#[derive(Debug, Clone, Copy)]
pub struct Xor<R, A> {
    pub ri: R,
    pub rj: R,
    pub a: A,
}

#[derive(Debug, Clone, Copy)]
pub struct Not<R, A> {
    pub ri: R,
    pub a: A,
}

#[derive(Debug, Clone, Copy)]
pub struct Add<R, A> {
    pub ri: R,
    pub rj: R,
    pub a: A,
}

#[derive(Debug, Clone, Copy)]
pub struct Sub<R, A> {
    pub ri: R,
    pub rj: R,
    pub a: A,
}

#[derive(Debug, Clone, Copy)]
pub struct Mull<R, A> {
    pub ri: R,
    pub rj: R,
    pub a: A,
}

#[derive(Debug, Clone, Copy)]
pub struct UMulh<R, A> {
    pub ri: R,
    pub rj: R,
    pub a: A,
}

#[derive(Debug, Clone, Copy)]
pub struct SMulh<R, A> {
    pub ri: R,
    pub rj: R,
    pub a: A,
}

impl SMulh<RegName, ImmediateOrRegName> {
    /// Returns the `(upper bits, lower bits, flag)` of signed multiplication.
    /// The flag is set if `a * b` is out of range of the word size.
    pub fn eval<const WORD_BITS: u32>(a: Word, b: Word) -> (Word, Word, bool) {
        let a = a.into_signed(WORD_BITS) as i128;
        let b = b.into_signed(WORD_BITS) as i128;

        let f = a * b;

        let lower = truncate::<WORD_BITS>(f as u128);
        let upper = truncate::<WORD_BITS>((f >> WORD_BITS) as u128);

        let m = 2i128.pow(WORD_BITS - 1);
        let flag = f >= m || f < -m;

        assert_eq!(f.is_negative(), upper.into_signed(WORD_BITS).is_negative());
        (upper, lower, flag)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct UDiv<R, A> {
    pub ri: R,
    pub rj: R,
    pub a: A,
}

#[derive(Debug, Clone, Copy)]
pub struct UMod<R, A> {
    pub ri: R,
    pub rj: R,
    pub a: A,
}

#[derive(Debug, Clone, Copy)]
pub struct Shl<R, A> {
    pub ri: R,
    pub rj: R,
    pub a: A,
}

#[derive(Debug, Clone, Copy)]
pub struct Shr<R, A> {
    pub ri: R,
    pub rj: R,
    pub a: A,
}

#[derive(Debug, Clone, Copy)]
pub struct Cmpe<R, A> {
    pub ri: R,
    pub a: A,
}

#[derive(Debug, Clone, Copy)]
pub struct Cmpa<R, A> {
    pub ri: R,
    pub a: A,
}

#[derive(Debug, Clone, Copy)]
pub struct Cmpae<R, A> {
    pub ri: R,
    pub a: A,
}

#[derive(Debug, Clone, Copy)]
pub struct Cmpg<R, A> {
    pub ri: R,
    pub a: A,
}

#[derive(Debug, Clone, Copy)]
pub struct Cmpge<R, A> {
    pub ri: R,
    pub a: A,
}

#[derive(Debug, Clone, Copy)]
pub struct Mov<R, A> {
    pub ri: R,
    pub a: A,
}

#[derive(Debug, Clone, Copy)]
pub struct CMov<R, A> {
    pub ri: R,
    pub a: A,
}

/// stall or halt (and the return value is `[A]u` )
#[derive(Debug, Clone, Copy)]
pub struct Jmp<A> {
    pub a: A,
}

/// stall or halt (and the return value is `[A]u` )
#[derive(Debug, Clone, Copy)]
pub struct CJmp<A> {
    pub a: A,
}

/// stall or halt (and the return value is `[A]u` )
#[derive(Debug, Clone, Copy)]
pub struct CnJmp<A> {
    pub a: A,
}

/// Store into ri the word in memory that is aligned to the `[A]w-th` byte.
#[derive(Debug, Clone, Copy)]
pub struct LoadW<R, A> {
    pub ri: R,
    pub a: A,
}

/// store `[ri]` at the word in memory that is aligned to the `[A]w-th` byte
#[derive(Debug, Clone, Copy)]
pub struct StoreW<R, A> {
    pub ri: R,
    pub a: A,
}

/// stall or halt (and the return value is `[A]u` )
#[derive(Debug, Clone, Copy)]
pub struct Answer<A> {
    pub a: A,
}

/// Conveniance aliases for Instructions type with unit type Arguments.
pub mod unit {

    pub type And = super::And<(), ()>;

    pub type Or = super::Or<(), ()>;

    pub type Xor = super::Xor<(), ()>;

    pub type Not = super::Not<(), ()>;

    pub type Add = super::Add<(), ()>;

    pub type Sub = super::Sub<(), ()>;

    pub type Mull = super::Mull<(), ()>;

    pub type UMulh = super::UMulh<(), ()>;

    pub type SMulh = super::SMulh<(), ()>;

    pub type UDiv = super::UDiv<(), ()>;

    pub type UMod = super::UMod<(), ()>;

    pub type Shl = super::Shl<(), ()>;

    pub type Shr = super::Shr<(), ()>;

    pub type Cmpe = super::Cmpe<(), ()>;

    pub type Cmpa = super::Cmpa<(), ()>;

    pub type Cmpae = super::Cmpae<(), ()>;

    pub type Cmpg = super::Cmpg<(), ()>;

    pub type Cmpge = super::Cmpge<(), ()>;

    pub type Mov = super::Mov<(), ()>;

    pub type CMov = super::CMov<(), ()>;

    pub type Jmp = super::Jmp<()>;

    pub type CJmp = super::CJmp<()>;

    pub type CnJmp = super::CnJmp<()>;

    pub type LoadW = super::LoadW<(), ()>;

    pub type StoreW = super::StoreW<(), ()>;

    pub type Answer = super::Answer<()>;
}
