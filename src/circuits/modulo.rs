// TODO add tests using dead code
#![allow(dead_code)]
use crate::assign::ConstraintSys;
use halo2_proofs::plonk::Constraints;
use halo2_proofs::poly::Rotation;
use halo2_proofs::{
    arithmetic::FieldExt,
    plonk::{Advice, Column, Selector},
};

#[derive(Debug, Clone, Copy)]
pub struct ModConfig<const WORD_BITS: u32> {
    /// A Selector denoting the extent of the exe table.
    s_table: Selector,
    /// An advice columns that acts as a selector for mod's gates.
    /// `Out.mod`
    s_mod: Column<Advice>,

    a: Column<Advice>,
    b: Column<Advice>,
    c: Column<Advice>,
    d: Column<Advice>,

    flag: Column<Advice>,
}

impl<const WORD_BITS: u32> ModConfig<WORD_BITS> {
    pub fn configure<F: FieldExt>(
        meta: &mut impl ConstraintSys<F, Column<Advice>>,
        s_table: Selector,
        s_mod: Column<Advice>,

        a: Column<Advice>,
        b: Column<Advice>,
        c: Column<Advice>,
        d: Column<Advice>,
        flag: Column<Advice>,
    ) -> Self {
        meta.cs().create_gate("mod", |meta| {
            let s_table = meta.query_selector(s_table);
            let s_mod = meta.query_advice(s_mod, Rotation::cur());

            let a = meta.query_advice(a, Rotation::cur());
            let b = meta.query_advice(b, Rotation::cur());
            let c = meta.query_advice(c, Rotation::cur());
            let d = meta.query_advice(d, Rotation::cur());
            let flag_next = meta.query_advice(flag, Rotation::next());

            Constraints::with_selector(
                s_table * s_mod,
                [flag_next * (b.clone() - d.clone()) + d - b * c - a],
            )
        });

        Self {
            s_table,
            s_mod,
            a,
            b,
            c,
            d,
            flag,
        }
    }
}
