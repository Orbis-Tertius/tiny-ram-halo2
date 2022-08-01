use proptest::proptest;
use std::{
    collections::BTreeMap,
    fmt::Display,
    ops::{BitAnd, BitOr, BitXor, Index, IndexMut},
};

// TODO make generic over word size and rep, or make logic uniform on u64 or u128.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Word(pub u32);

impl Word {
    pub const fn try_from_signed(s: i32, word_bits: u32) -> Option<Word> {
        let min = -2i32.pow(word_bits - 1);
        if s > -min - 1 || s < min {
            None
        } else if s >= 0 {
            Some(Word(s as u32))
        } else {
            let u = 2i64.pow(word_bits);
            Some(Word((s as i64 + u) as u32))
        }
    }

    pub fn into_signed(self, word_bits: u32) -> i32 {
        if (1 << (word_bits - 1)) & self.0 == 0 {
            self.0 as _
        } else {
            (self.0 as i64 - 2i64.pow(word_bits)) as _
        }
    }
}

proptest! {
    #[test]
    fn from_signed_test(s in -2i32.pow(8 - 1)..2i32.pow(8 - 1) - 1) {
        assert_eq!(Word::try_from_signed(s.into(), 8), Some(Word(s as i8 as u8 as u32)));
    }

    #[test]
    fn from_signed_test_too_high(s in 2i32.pow(8 - 1)..i32::MAX) {
        assert_eq!(Word::try_from_signed(s.into(), 8), None);
    }

    #[test]
    fn from_signed_test_too_low(s in i32::MIN..(-2i32.pow(8 - 1)) - 1) {
        assert_eq!(Word::try_from_signed(s.into(), 8), None);
    }

    #[test]
    fn to_signed_test(s in -2i32.pow(8 - 1)..2i32.pow(8 - 1) - 1) {
        let w = Word::try_from_signed(s.into(), 8);
        assert_eq!(w, Some(Word(s as i8 as u8 as u32)));
        assert_eq!(w.unwrap().into_signed(8), s);
    }
}

impl From<Word> for u128 {
    fn from(w: Word) -> Self {
        w.0 as u128
    }
}

impl BitAnd for Word {
    type Output = Word;

    fn bitand(self, rhs: Self) -> Self::Output {
        Word(self.0 & rhs.0)
    }
}

impl BitOr for Word {
    type Output = Word;

    fn bitor(self, rhs: Self) -> Self::Output {
        Word(self.0 | rhs.0)
    }
}

impl BitXor for Word {
    type Output = Word;

    fn bitxor(self, rhs: Self) -> Self::Output {
        Word(self.0 ^ rhs.0)
    }
}

/// Execution step count.
/// Time counts from 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Time(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Address(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ProgCount(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct RegName(pub u8);

#[derive(Debug, Clone)]
pub struct Trace<const WORD_BITS: u32, const REG_COUNT: usize> {
    pub prog: Program,
    pub exe: Vec<Step<REG_COUNT>>,
    pub mem: Mem<WORD_BITS>,
    pub ans: Word,
}

#[derive(Debug, Clone)]
pub struct Mem<const WORD_BITS: u32> {
    // A map from an address to a time ordered vector of access.
    pub address: BTreeMap<Address, Accesses>,
}

impl<const WORD_BITS: u32> Mem<WORD_BITS> {
    /// Instead of providing two read only tapes as the TinyRAM specification does,
    /// We take the aproach from page 13 of the Arya paper, and write the tapes to memory.
    pub fn new(primary_tape: &[Word], auxiliary_tape: &[Word]) -> Self {
        assert_eq!(WORD_BITS % 8, 0);

        Mem {
            address: primary_tape
                .iter()
                .chain(auxiliary_tape.iter())
                .cloned()
                .enumerate()
                .map(|(i, word)| {
                    let address = Address(i as u32 * WORD_BITS);
                    // In TinyRAM 2.0 Preamble they specify reading the primary tape
                    // TODO match the spec, and figure out the non-deterministic tapes location.
                    (address, Accesses::init_memory(address, word))
                })
                .collect(),
        }
    }
    fn access(&mut self, address: Address) -> &mut Accesses {
        self.address
            .entry(address)
            // Perhaps we should panic on loads before stores.
            // Probably not in tests.
            .or_insert_with(|| Accesses::init_memory(address, Word(0)))
    }

    fn load(&mut self, address: Address, time: Time, pc: ProgCount) -> Word {
        let accesses = self.access(address);
        let value = accesses.0.last().unwrap().value();
        accesses.0.push(Access::Load {
            value,
            time,
            pc,
            address,
        });
        value
    }

    fn store(&mut self, address: Address, time: Time, pc: ProgCount, value: Word) {
        assert!(value.0 <= 2u32.pow(WORD_BITS as u32));
        let accesses = self.access(address);
        accesses.0.push(Access::Store {
            value,
            time,
            pc,
            address,
        });
    }
}

// A time ordered vector of memory instructions.
#[derive(Debug, Clone, Default)]
pub struct Accesses(pub Vec<Access>);

impl Accesses {
    fn init_memory(address: Address, value: Word) -> Accesses {
        Accesses(vec![Access::Init { address, value }])
    }

    pub fn initial_value(&self) -> Option<Word> {
        match self.0.first() {
            Some(Access::Init { value, .. }) => Some(*value),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    Init {
        /// A word aligned address.
        address: Address,
        // This is redundant, but worth having.
        value: Word,
    },
    Store {
        /// A word aligned address.
        address: Address,
        time: Time,
        pc: ProgCount,
        value: Word,
    },
    Load {
        /// A word aligned address.
        address: Address,
        time: Time,
        pc: ProgCount,
        // This is redundant, but worth having.
        value: Word,
    },
}

impl Access {
    pub fn address(&self) -> Address {
        match self {
            Access::Init { address, .. }
            | Access::Store { address, .. }
            | Access::Load { address, .. } => *address,
        }
    }

    pub fn value(&self) -> Word {
        match self {
            Access::Init { value, .. }
            | Access::Store { value, .. }
            | Access::Load { value, .. } => *value,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Step<const REG_COUNT: usize> {
    pub time: Time,
    pub pc: ProgCount,
    pub instruction: Instruction,
    pub regs: Registers<REG_COUNT, Word>,
    pub flag: bool,
    pub v_addr: Option<Word>,
}

/// Docs for a variant are on each variant's struct,
/// They can also be found on page 9 of the TinyRAM Architecture Specification v2.000.
#[derive(Debug, Clone, Copy)]
pub enum Instruction {
    And(And),
    Or(Or),
    Xor(Xor),
    Not(Not),
    Add(Add),
    Sub(Sub),
    Mull(Mull),
    UMulh(UMulh),
    SMulh(SMulh),
    UDiv(UDiv),
    UMod(UMod),
    Shl(Shl),
    Shr(Shr),
    /// compare equal
    Cmpe(Cmpe),
    /// compare above, unsigned
    Cmpa(Cmpa),
    /// compare above or equal, unsigned
    Cmpae(Cmpae),
    // compare greater signed
    Cmpg(Cmpg),
    /// compare greater or equal, signed
    Cmpge(Cmpge),
    Mov(Mov),
    CMov(CMov),
    Jmp(Jmp),
    CJmp(CJmp),
    CnJmp(CnJmp),
    StoreW(StoreW),
    LoadW(LoadW),
    Answer(Answer),
}

impl Instruction {
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

impl Display for Instruction {
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

#[derive(PartialEq, Debug, Clone, Copy)]
pub enum ImmediateOrRegName {
    Immediate(Word),
    RegName(RegName),
}

impl ImmediateOrRegName {
    pub fn immediate(self) -> Option<Word> {
        match self {
            ImmediateOrRegName::Immediate(w) => Some(w),
            ImmediateOrRegName::RegName(_) => None,
        }
    }
}

impl Display for ImmediateOrRegName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ImmediateOrRegName::Immediate(w) => write!(f, "{:0b} ", w.0),
            ImmediateOrRegName::RegName(r) => write!(f, "r{} ", r.0),
        }
    }
}

impl ImmediateOrRegName {
    pub fn get<const REG_COUNT: usize>(
        &self,
        regs: &Registers<REG_COUNT, Word>,
    ) -> Word {
        match self {
            ImmediateOrRegName::Immediate(w) => *w,
            ImmediateOrRegName::RegName(r) => regs[*r],
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Registers<const REG_COUNT: usize, T>(pub [T; REG_COUNT]);

impl<const REG_COUNT: usize, T> Registers<REG_COUNT, T> {
    pub fn init_with(mut f: impl FnMut() -> T) -> Self {
        // We cannot write `[meta.advice_column(); REG_COUNT]`,
        // That would produce an array of the same advice copied REG_COUNT times.
        //
        // See Rust's array initialization semantics.
        Registers([0; REG_COUNT].map(|_| f()))
    }
}

impl<const REG_COUNT: usize, T> From<[T; REG_COUNT]> for Registers<REG_COUNT, T> {
    fn from(arr: [T; REG_COUNT]) -> Self {
        Registers(arr)
    }
}

impl<const REG_COUNT: usize, A> Registers<REG_COUNT, A> {
    pub fn convert<B: From<A>>(self) -> Registers<REG_COUNT, B> {
        Registers(self.0.map(B::from))
    }
}

impl<const REG_COUNT: usize, T: Copy> Registers<REG_COUNT, T> {
    pub fn set(mut self, i: RegName, v: T) -> Self {
        self[i] = v;
        self
    }
}

impl<const REG_COUNT: usize> Default for Registers<REG_COUNT, Word> {
    fn default() -> Self {
        Registers([Word::default(); REG_COUNT])
    }
}

impl<const REG_COUNT: usize, T> Index<RegName> for Registers<REG_COUNT, T> {
    type Output = T;

    fn index(&self, index: RegName) -> &Self::Output {
        &self.0[index.0 as usize]
    }
}

impl<const REG_COUNT: usize, T> IndexMut<RegName> for Registers<REG_COUNT, T> {
    fn index_mut(&mut self, index: RegName) -> &mut Self::Output {
        &mut self.0[index.0 as usize]
    }
}

/// compute bitwise AND of `[rj]` and `[A]` and store result in ri
#[derive(Debug, Clone, Copy)]
pub struct And {
    pub ri: RegName,
    pub rj: RegName,
    pub a: ImmediateOrRegName,
}

/// compute bitwise OR of `[rj]` and `[A]` and store result in ri
#[derive(Debug, Clone, Copy)]
pub struct Or {
    pub ri: RegName,
    pub rj: RegName,
    pub a: ImmediateOrRegName,
}

/// compute bitwise OR of `[rj]` and `[A]` and store result in ri
#[derive(Debug, Clone, Copy)]
pub struct Xor {
    pub ri: RegName,
    pub rj: RegName,
    pub a: ImmediateOrRegName,
}

#[derive(Debug, Clone, Copy)]
pub struct Not {
    pub ri: RegName,
    pub a: ImmediateOrRegName,
}

#[derive(Debug, Clone, Copy)]
pub struct Add {
    pub ri: RegName,
    pub rj: RegName,
    pub a: ImmediateOrRegName,
}

#[derive(Debug, Clone, Copy)]
pub struct Sub {
    pub ri: RegName,
    pub rj: RegName,
    pub a: ImmediateOrRegName,
}

#[derive(Debug, Clone, Copy)]
pub struct Mull {
    pub ri: RegName,
    pub rj: RegName,
    pub a: ImmediateOrRegName,
}

#[derive(Debug, Clone, Copy)]
pub struct UMulh {
    pub ri: RegName,
    pub rj: RegName,
    pub a: ImmediateOrRegName,
}

#[derive(Debug, Clone, Copy)]
pub struct SMulh {
    pub ri: RegName,
    pub rj: RegName,
    pub a: ImmediateOrRegName,
}

impl SMulh {
    /// Returns the `(upper bits, lower bits, flag)` of signed multiplication.
    /// The flag is set if `a * b` is out of range of the word size.
    pub fn eval<const WORD_BITS: u32>(a: Word, b: Word) -> (Word, Word, bool) {
        let a = a.into_signed(WORD_BITS) as i128;
        let b = b.into_signed(WORD_BITS) as i128;

        let f = a * b;

        let lower = truncate::<WORD_BITS>(f as u128);
        let upper = truncate::<WORD_BITS>((f >> WORD_BITS) as u128);

        let m = 2i128.pow(WORD_BITS - 1);
        let flag = if f >= m || f < -m { true } else { false };

        assert_eq!(f.is_negative(), upper.into_signed(WORD_BITS).is_negative());
        (upper, lower, flag)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct UDiv {
    pub ri: RegName,
    pub rj: RegName,
    pub a: ImmediateOrRegName,
}

#[derive(Debug, Clone, Copy)]
pub struct UMod {
    pub ri: RegName,
    pub rj: RegName,
    pub a: ImmediateOrRegName,
}

#[derive(Debug, Clone, Copy)]
pub struct Shl {
    pub ri: RegName,
    pub rj: RegName,
    pub a: ImmediateOrRegName,
}

#[derive(Debug, Clone, Copy)]
pub struct Shr {
    pub ri: RegName,
    pub rj: RegName,
    pub a: ImmediateOrRegName,
}

#[derive(Debug, Clone, Copy)]
pub struct Cmpe {
    pub ri: RegName,
    pub a: ImmediateOrRegName,
}

#[derive(Debug, Clone, Copy)]
pub struct Cmpa {
    pub ri: RegName,
    pub a: ImmediateOrRegName,
}

#[derive(Debug, Clone, Copy)]
pub struct Cmpae {
    pub ri: RegName,
    pub a: ImmediateOrRegName,
}

#[derive(Debug, Clone, Copy)]
pub struct Cmpg {
    pub ri: RegName,
    pub a: ImmediateOrRegName,
}

#[derive(Debug, Clone, Copy)]
pub struct Cmpge {
    pub ri: RegName,
    pub a: ImmediateOrRegName,
}

#[derive(Debug, Clone, Copy)]
pub struct Mov {
    pub ri: RegName,
    pub a: ImmediateOrRegName,
}

#[derive(Debug, Clone, Copy)]
pub struct CMov {
    pub ri: RegName,
    pub a: ImmediateOrRegName,
}

/// stall or halt (and the return value is `[A]u` )
#[derive(Debug, Clone, Copy)]
pub struct Jmp {
    pub a: ImmediateOrRegName,
}

/// stall or halt (and the return value is `[A]u` )
#[derive(Debug, Clone, Copy)]
pub struct CJmp {
    pub a: ImmediateOrRegName,
}

/// stall or halt (and the return value is `[A]u` )
#[derive(Debug, Clone, Copy)]
pub struct CnJmp {
    pub a: ImmediateOrRegName,
}

/// Store into ri the word in memory that is aligned to the `[A]w-th` byte.
#[derive(Debug, Clone, Copy)]
pub struct LoadW {
    pub ri: RegName,
    pub a: ImmediateOrRegName,
}

/// store `[ri]` at the word in memory that is aligned to the `[A]w-th` byte
#[derive(Debug, Clone, Copy)]
pub struct StoreW {
    pub ri: RegName,
    pub a: ImmediateOrRegName,
}

/// stall or halt (and the return value is `[A]u` )
#[derive(Debug, Clone, Copy)]
pub struct Answer {
    pub a: ImmediateOrRegName,
}

// We don't support read, load.b, or store.b

pub fn truncate<const WORD_BITS: u32>(word: u128) -> Word {
    Word((word & ((2u128.pow(WORD_BITS)) - 1)) as u32)
}

/// A bit mask for getting the upper word.
///
/// We are matching the Haskell TinyRAM emulator.
/// github.com/Orbis-Tertius/tinyram/blob/main/src/TinyRAM/Params.hs
pub const fn get_word_size_bit_mask_msb(word_bits: u32) -> u128 {
    let m = 2u128.pow(word_bits);
    m * (m - 1)
}

#[derive(Debug, Clone, Default)]
pub struct Program(pub Vec<Instruction>);

impl Program {
    pub fn eval<const WORD_BITS: u32, const REG_COUNT: usize>(
        self,
        mut mem: Mem<WORD_BITS>,
    ) -> Trace<WORD_BITS, REG_COUNT> {
        let prog = self;
        let mut regs = Registers::<REG_COUNT, Word>::default();
        let mut pc = ProgCount(0);
        let mut time = Time(1);
        let mut exe = Vec::with_capacity(100);
        let mut flag = false;
        let ans = loop {
            let instruction = *prog
                .0
                .get(pc.0 as usize)
                .expect("Program did not Answer 0 or 1.");
            exe.push(Step {
                time,
                pc,
                instruction,
                regs,
                flag,
                v_addr: if let Instruction::LoadW(LoadW { a, .. }) = instruction {
                    let a = a.get(&regs).0;
                    Some(mem.load(Address(a), time, pc))
                } else {
                    None
                },
            });
            match instruction {
                Instruction::And(And { ri, rj, a }) => {
                    regs[ri] = regs[rj] & a.get(&regs);
                    flag = regs[ri].0 == 0;
                }
                Instruction::Or(Or { ri, rj, a }) => {
                    regs[ri] = regs[rj] | a.get(&regs);
                    flag = regs[ri].0 == 0;
                }
                Instruction::Xor(Xor { ri, rj, a }) => {
                    regs[ri] = regs[rj] ^ a.get(&regs);
                    flag = regs[ri].0 == 0;
                }
                Instruction::Not(Not { ri, a }) => {
                    regs[ri] = Word(!a.get(&regs).0);
                    flag = regs[ri].0 == 0;
                }
                Instruction::Add(Add { ri, rj, a }) => {
                    let r = regs[rj].0 as u128 + a.get(&regs).0 as u128;

                    regs[ri] = truncate::<WORD_BITS>(r);
                    flag = (r & get_word_size_bit_mask_msb(WORD_BITS)) != 0;
                }
                Instruction::Sub(Sub { ri, rj, a }) => {
                    let r = regs[rj].0 as u128 + 2u128.pow(WORD_BITS)
                        - a.get(&regs).0 as u128;
                    regs[ri] = truncate::<WORD_BITS>(r);
                    flag = (r & (get_word_size_bit_mask_msb(WORD_BITS))) == 0;
                }
                Instruction::Mull(Mull { ri, rj, a }) => {
                    // compute [rj]u × [A]u and store least significant bits of result in ri
                    let r = regs[rj].0 as u128 * a.get(&regs).0 as u128;
                    regs[ri] = Word((r % 2u128.pow(WORD_BITS)) as u32);

                    flag = r < 2u128.pow(WORD_BITS);
                }
                Instruction::UMulh(UMulh { ri, rj, a }) => {
                    // compute [rj]u × [A]u and store most significant bits of result in ri
                    let r = regs[rj].0 as u128 * a.get(&regs).0 as u128;
                    regs[ri] = truncate::<WORD_BITS>(r >> WORD_BITS);
                    flag = regs[ri].0 == 0;
                }
                Instruction::SMulh(SMulh { ri, rj, a }) => {
                    let a = a.get(&regs);
                    let rj = regs[rj];

                    let (upper, _lower, _f) = SMulh::eval::<WORD_BITS>(a, rj);
                    regs[ri] = upper;
                    flag = upper.0 == 0;
                }
                Instruction::UDiv(UDiv { ri, rj, a }) => {
                    let a = a.get(&regs).0;
                    let y = if a == 0 { 0 } else { regs[rj].0 / a };
                    regs[ri] = Word(y);
                    flag = a == 0;
                }
                Instruction::UMod(UMod { ri, rj, a }) => {
                    let a = a.get(&regs).0;
                    let y = if a == 0 { 0 } else { regs[rj].0 % a };
                    regs[ri] = Word(y);
                    flag = a == 0;
                }
                Instruction::Shl(Shl { ri, rj, a }) => {
                    let a = a.get(&regs).0;
                    let rj = regs[rj].0;
                    regs[ri] = truncate::<WORD_BITS>((rj << a) as _);
                    flag = (rj & (2u32.pow(WORD_BITS - 1))) != 0;
                }
                Instruction::Shr(Shr { ri, rj, a }) => {
                    let a = a.get(&regs).0;
                    let rj = regs[rj].0;
                    regs[ri] = Word(rj >> a);
                    flag = (rj & 1) != 0
                }
                Instruction::Cmpe(Cmpe { ri, a }) => flag = a.get(&regs) == regs[ri],
                Instruction::Cmpa(Cmpa { ri, a }) => flag = regs[ri] > a.get(&regs),
                Instruction::Cmpae(Cmpae { ri, a }) => {
                    flag = regs[ri] >= a.get(&regs)
                }
                Instruction::Cmpg(Cmpg { ri, a }) => {
                    let ri = signed_arithmetic::decode_signed::<WORD_BITS>(regs[ri]);
                    let a =
                        signed_arithmetic::decode_signed::<WORD_BITS>(a.get(&regs));
                    flag = ri > a;
                }
                Instruction::Cmpge(Cmpge { ri, a }) => {
                    let ri = signed_arithmetic::decode_signed::<WORD_BITS>(regs[ri]);
                    let a =
                        signed_arithmetic::decode_signed::<WORD_BITS>(a.get(&regs));
                    flag = ri >= a;
                }
                Instruction::Mov(Mov { ri, a }) => regs[ri] = a.get(&regs),
                Instruction::CMov(CMov { ri, a }) => {
                    if flag {
                        regs[ri] = a.get(&regs)
                    }
                }
                Instruction::Jmp(Jmp { a }) => pc = ProgCount(a.get(&regs).0),
                Instruction::CJmp(CJmp { a }) => {
                    if flag {
                        pc = ProgCount(a.get(&regs).0)
                    } else {
                        pc.0 += 1
                    }
                }
                Instruction::CnJmp(CnJmp { a }) => {
                    if !flag {
                        pc = ProgCount(a.get(&regs).0)
                    } else {
                        pc.0 += 1
                    }
                }
                Instruction::LoadW(LoadW { ri, a }) => {
                    let a = a.get(&regs).0;
                    regs[ri] = mem.load(Address(a), time, pc);
                }
                Instruction::StoreW(StoreW { ri, a }) => {
                    mem.store(Address(a.get(&regs).0), time, pc, regs[ri])
                }
                Instruction::Answer(Answer { a }) => break a.get(&regs),
            };

            time.0 += 1;
            if !matches!(
                instruction,
                Instruction::Jmp(_) | Instruction::CnJmp(_) | Instruction::CJmp(_)
            ) {
                pc.0 += 1
            };
        };
        Trace {
            prog,
            mem,
            ans,
            exe,
        }
    }
}

/// github.com/Orbis-Tertius/tinyram/blob/main/src/TinyRAM/SignedArithmetic.hs
mod signed_arithmetic {
    use super::Word;

    pub fn decode_signed<const WORD_BITS: u32>(w: Word) -> i64 {
        let m = 2i64.pow(WORD_BITS - 1);
        let w = w.0 as i64;
        (w & (m - 1)) - (w & m)
    }
}

#[test]
fn trace_load_and_store_ans_test() {
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
        Instruction::StoreW(StoreW {
            ri: RegName(1),
            a: ImmediateOrRegName::Immediate(Word(1)),
        }),
        Instruction::Answer(Answer {
            a: ImmediateOrRegName::RegName(RegName(1)),
        }),
    ]);

    let trace = prog.eval::<8, 8>(Mem::new(&[Word(0b1)], &[]));
    assert_eq!(trace.ans.0, 0b1);
    assert_eq!(
        trace.mem.address.get(&Address(1)).unwrap().0[1],
        Access::Store {
            address: Address(1),
            time: Time(3),
            pc: ProgCount(2),
            value: Word(0b1)
        }
    );
}
