use std::fmt::Debug;

use halo2_proofs::{
    arithmetic::FieldExt,
    plonk::{
        self, Advice, Column, ConstraintSystem, Constraints, Expression, Selector,
    },
    poly::Rotation,
};

use crate::{assign::PushRow, trace::Registers};

/// This corresponds to sch in the paper.
/// The meaning of 0, and 1 is inverted relative to the paper.
/// A selector value of 0 denotes an unchanged cell.
///
/// This inversion will enable use of the selection vector combining optimization.
#[derive(Debug, Clone, Copy)]
pub struct ChangedSelectors<const REG_COUNT: usize, T> {
    pub regs: Registers<REG_COUNT, T>,
    /// Unlike all the other entries, `pc: false` denotes a incremented program count.
    pub pc: T,
    pub flag: T,
}

impl<const REG_COUNT: usize, T> ChangedSelectors<REG_COUNT, T> {
    pub fn new(mut new_fn: impl FnMut() -> T) -> Self {
        ChangedSelectors {
            regs: Registers([0usize; REG_COUNT].map(|_| new_fn())),
            pc: new_fn(),
            flag: new_fn(),
        }
    }

    pub fn push_cells<F: FieldExt, R: PushRow<F, T>>(
        self,
        region: &mut R,
        vals: ChangedSelectors<REG_COUNT, bool>,
    ) -> Result<(), plonk::Error>
    where
        T: Debug,
    {
        let Self { regs, pc, flag } = self;

        for (rc, rv) in regs.0.into_iter().zip(vals.regs.0.into_iter()) {
            region.push_cell(rc, rv.into()).unwrap();
        }
        region.push_cell(pc, vals.pc.into())?;
        region.push_cell(flag, vals.flag.into())?;

        Ok(())
    }

    pub fn convert<B: From<T>>(self) -> ChangedSelectors<REG_COUNT, B> {
        ChangedSelectors {
            regs: self.regs.convert(),
            pc: self.pc.into(),
            flag: self.flag.into(),
        }
    }
}

impl<const REG_COUNT: usize> ChangedSelectors<REG_COUNT, Column<Advice>> {
    pub fn unchanged_gate<F: FieldExt>(
        &self,
        meta: &mut ConstraintSystem<F>,
        s_table: Selector,

        // TODO Consider refactoring ChangedSelectors into a new type around `State {regs, pc, flag}`
        regs: Registers<REG_COUNT, Column<Advice>>,
        pc: Column<Advice>,
        flag: Column<Advice>,
    ) {
        meta.create_gate("unchanged", |meta| {
            let one = Expression::Constant(F::one());

            let s_table = meta.query_selector(s_table);

            let ch_pc = meta.query_advice(self.pc, Rotation::cur());
            let pc_n = meta.query_advice(pc, Rotation::next());
            let pc = meta.query_advice(pc, Rotation::cur());

            let ch_flag = meta.query_advice(self.flag, Rotation::cur());
            let flag_n = meta.query_advice(flag, Rotation::next());
            let flag = meta.query_advice(flag, Rotation::cur());

            let mut constraints = vec![
                (one.clone() - ch_pc) * (pc + one.clone() - pc_n),
                (one.clone() - ch_flag) * (flag - flag_n),
            ];

            constraints.extend(self.regs.0.iter().zip(regs.0.iter()).map(
                |(ch_r, r)| {
                    let ch_r = meta.query_advice(*ch_r, Rotation::cur());
                    let r_n = meta.query_advice(*r, Rotation::next());
                    let r = meta.query_advice(*r, Rotation::cur());

                    (one.clone() - ch_r) * (r - r_n)
                },
            ));

            Constraints::with_selector(s_table, constraints)
        });
    }
}
