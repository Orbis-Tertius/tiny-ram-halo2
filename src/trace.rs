use std::{
    collections::BTreeMap,
    fmt::Display,
    ops::{BitAnd, Index, IndexMut},
};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Word(pub usize);

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Time(pub usize);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Address(pub usize);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ProgCount(pub usize);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct RegName(pub usize);

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
                    let address = Address(i * WORD_BITS as usize);
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
        assert!(value.0 <= 2usize.pow(WORD_BITS as u32));
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
}

/// Docs for a variant are on each variant's struct,
/// They can also be found on page 9 of the TinyRAM Architecture Specification v2.000.
#[derive(Debug, Clone, Copy)]
pub enum Instruction {
    And(And),
    LoadW(LoadW),
    StoreW(StoreW),
    Answer(Answer),
}

impl Instruction {
    pub fn name(&self) -> &str {
        match self {
            Instruction::And(_) => "and",
            Instruction::LoadW(_) => "load.w",
            Instruction::StoreW(_) => "store.w",
            Instruction::Answer(_) => "answer",
        }
    }

    pub fn ri(&self) -> Option<RegName> {
        match self {
            Instruction::And(And { ri, .. })
            | Instruction::LoadW(LoadW { ri, .. })
            | Instruction::StoreW(StoreW { ri, .. }) => Some(*ri),
            Instruction::Answer(_) => None,
        }
    }

    pub fn rj(&self) -> Option<RegName> {
        match self {
            Instruction::And(And { rj, .. }) => Some(*rj),
            Instruction::Answer(_)
            | Instruction::StoreW(_)
            | Instruction::LoadW(_) => None,
        }
    }

    pub fn a(&self) -> ImmediateOrRegName {
        match self {
            Instruction::And(And { a, .. })
            | Instruction::LoadW(LoadW { a, .. })
            | Instruction::StoreW(StoreW { a, .. })
            | Instruction::Answer(Answer { a }) => *a,
        }
    }

    /// See TinyRAM 2.0 spec (page 16)
    /// The op code is the first field (`#1` in the table) of the binary instruction encoding.
    pub fn opcode(&self) -> u128 {
        match self {
            Instruction::And(_) => 0b00000,
            Instruction::LoadW(_) => 0b11101,
            Instruction::StoreW(_) => 0b11100,
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
            Instruction::And(And { ri, rj, a }) => {
                write!(f, "r{} ", ri.0)?;
                write!(f, "r{} ", rj.0)?;
                write!(f, "{}", a)
            }
            Instruction::LoadW(LoadW { ri, a })
            | Instruction::StoreW(StoreW { ri, a }) => {
                write!(f, "r{} ", ri.0)?;
                write!(f, "{}", a)
            }
            Instruction::Answer(Answer { a }) => write!(f, "{}", a),
        }
    }
}

#[derive(Debug, Clone, Copy)]
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
    fn get<const REG_COUNT: usize>(
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
        &self.0[index.0]
    }
}

impl<const REG_COUNT: usize, T> IndexMut<RegName> for Registers<REG_COUNT, T> {
    fn index_mut(&mut self, index: RegName) -> &mut Self::Output {
        &mut self.0[index.0]
    }
}

/// compute bitwise AND of `[rj]` and `[A]` and store result in ri
#[derive(Debug, Clone, Copy)]
pub struct And {
    pub ri: RegName,
    pub rj: RegName,
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
        let mut time = Time(0);
        let mut exe = Vec::with_capacity(100);
        let ans = loop {
            let instruction =
                *prog.0.get(pc.0).expect("Program did not Answer 0 or 1.");
            exe.push(Step {
                time,
                pc,
                instruction,
                regs,
            });
            match instruction {
                Instruction::And(And { ri, rj, a }) => {
                    regs[ri] = regs[rj] & a.get(&regs)
                }
                Instruction::LoadW(LoadW { ri, a }) => {
                    regs[ri] = mem.load(Address(a.get(&regs).0), time, pc);
                }
                Instruction::StoreW(StoreW { ri, a }) => {
                    mem.store(Address(a.get(&regs).0), time, pc, regs[ri])
                }
                Instruction::Answer(Answer { a }) => break a.get(&regs),
            };

            time.0 += 1;
            pc.0 += 1;
        };
        Trace {
            prog,
            mem,
            ans,
            exe,
        }
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
            time: Time(2),
            pc: ProgCount(2),
            value: Word(0b1)
        }
    );
}
