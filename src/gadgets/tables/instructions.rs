use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::Region,
    plonk::{Advice, Column, ConstraintSystem, Selector},
};

use crate::{
    gadgets::and::{AndChip, AndConfig},
    trace::{self, And, Answer, ImmediateOrRegName, LoadW, StoreW},
};

use super::aux::TempVarSelectors;

/// These will later be replaced with the 9 plus flags method from Arya page 22.
#[derive(Debug, Clone, Copy)]
pub struct Instructions<const WORD_BITS: u32, const REG_COUNT: usize> {
    pub and: (Selector, AndConfig),
    pub load: Selector,
    pub store: Selector,
    pub answer: Selector,
}

impl<const WORD_BITS: u32, const REG_COUNT: usize>
    Instructions<WORD_BITS, REG_COUNT>
{
    pub fn new_configured<F: FieldExt>(
        meta: &mut ConstraintSystem<F>,
    ) -> Instructions<WORD_BITS, REG_COUNT> {
        let and = meta.selector();

        let and_config = {
            let advice = [meta.advice_column(), meta.advice_column()];
            let constant = meta.fixed_column();
            AndChip::<F, WORD_BITS>::configure(meta, advice, constant)
        };

        let load = meta.selector();
        let store = meta.selector();
        let answer = meta.selector();

        Instructions {
            and: (and, and_config),
            load,
            store,
            answer,
        }
    }

    /// TODO recompute instruction here, as an extra check.
    /// TODO set immediate selector in this match.
    /// TODO multiplex registers into temp vars, and set temp var selectors
    pub fn syn<F: FieldExt>(
        &self,
        immediate: Column<Advice>,
        s: TempVarSelectors<REG_COUNT>,
        region: &mut Region<F>,
        inst: trace::Instruction,
    ) {
        let assign_immediate = |region: &mut Region<F>, a| {
            if let ImmediateOrRegName::Immediate(word) = a {
                region
                    .assign_advice(
                        || format!("immediate: {:0b}", word.0),
                        immediate,
                        0,
                        || Ok(F::from_u128(word.0 as u128)),
                    )
                    .unwrap();
            }
            // Else immediate is zero
        };
        match inst {
            trace::Instruction::And(And { ri, rj, a }) => {
                match a {
                    ImmediateOrRegName::Immediate(_) => {
                        s.a.row.immediate.enable(region, 0).unwrap()
                    }
                    ImmediateOrRegName::RegName(r) => {
                        s.a.row.regs[r.0].enable(region, 0).unwrap()
                    }
                };
                s.b.row.regs[rj.0].enable(region, 0).unwrap();
                s.c.row_next.regs[ri.0].enable(region, 0).unwrap();



                self.and.0.enable(region, 0).unwrap();
                assign_immediate(region, a)
            }
            trace::Instruction::LoadW(LoadW { ri, a }) => {
                // page 34 fig 10.
                s.a.row.address.enable(region, 0).unwrap();
                s.b.row_next.regs[ri.0].enable(region, 0).unwrap();
                // TODO set sch and sout

                self.load.enable(region, 0).unwrap();
                assign_immediate(region, a)
            }
            trace::Instruction::StoreW(StoreW { ri, a }) => {
                s.a.row.address.enable(region, 0).unwrap();
                s.b.row.regs[ri.0].enable(region, 0).unwrap();

                self.store.enable(region, 0).unwrap();
                assign_immediate(region, a)
            }
            trace::Instruction::Answer(Answer { a }) => {
                // TODO answer Instruction selectors
                // This is not well specified by the paper (page 35).

                self.answer.enable(region, 0).unwrap();
                assign_immediate(region, a)
            }
        }
    }
}
