// TODO add tests using dead code
#![allow(dead_code)]
use crate::assign::ConstraintSys;
use halo2_proofs::plonk::Constraints;
use halo2_proofs::{
    arithmetic::FieldExt,
    plonk::{Advice, Column, Selector},
    poly::Rotation,
};

#[derive(Debug, Clone, Copy)]
pub struct Flag1Config<const WORD_BITS: u32> {
    /// A Selector denoting the extent of the exe table.
    s_table: Selector,
    s_flag1: Column<Advice>,

    c: Column<Advice>,
    flag: Column<Advice>,
}

impl<const WORD_BITS: u32> Flag1Config<WORD_BITS> {
    pub fn configure<F: FieldExt>(
        meta: &mut impl ConstraintSys<F, Column<Advice>>,
        s_table: Selector,
        s_flag1: Column<Advice>,

        c: Column<Advice>,
        flag: Column<Advice>,
    ) -> Self {
        meta.cs().create_gate("flag1", |meta| {
            let s_table = meta.query_selector(s_table);
            let s_flag1 = meta.query_advice(s_flag1, Rotation::cur());

            let c = meta.query_advice(c, Rotation::cur());
            let flag_n = meta.query_advice(flag, Rotation::next());

            Constraints::with_selector(s_table * s_flag1, [flag_n * c])
        });

        Self {
            s_table,
            s_flag1,
            c,
            flag,
        }
    }
}
