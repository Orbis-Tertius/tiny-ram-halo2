use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::Region,
    plonk::{Advice, Column, ConstraintSystem, Selector},
};

use crate::{
    gadgets::and::{AndChip, AndConfig},
    trace::{self, And, Answer, ImmediateOrRegName, LoadW, StoreW},
};

/// These will later be replaced with the 9 plus flags method from Arya page 22.
#[derive(Debug, Clone, Copy)]
pub struct Instructions<const WORD_BITS: u32> {
    pub and: (Selector, AndConfig),
    pub load: Selector,
    pub store: Selector,
    pub answer: Selector,
}

impl<const WORD_BITS: u32> Instructions<WORD_BITS> {
    pub fn new_configured<F: FieldExt>(
        meta: &mut ConstraintSystem<F>,
    ) -> Instructions<WORD_BITS> {
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
                self.and.0.enable(region, 0).unwrap();
                assign_immediate(region, a)
            }
            trace::Instruction::LoadW(LoadW { ri, a }) => {
                self.load.enable(region, 0).unwrap();
                assign_immediate(region, a)
            }
            trace::Instruction::StoreW(StoreW { ri, a }) => {
                self.store.enable(region, 0).unwrap();
                assign_immediate(region, a)
            }
            trace::Instruction::Answer(Answer { a }) => {
                self.answer.enable(region, 0).unwrap();
                assign_immediate(region, a)
            }
        }
    }
}
