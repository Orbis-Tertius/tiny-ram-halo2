use crate::assign::ConstraintSys;
use halo2_proofs::plonk::{Constraints, Expression};
use halo2_proofs::poly::Rotation;
use halo2_proofs::{
    arithmetic::FieldExt,
    plonk::{Advice, Column, Selector},
};

#[derive(Debug, Clone, Copy)]
pub struct ProdConfig<const WORD_BITS: u32> {
    /// A Selector denoting the extent of the exe table.
    s_table: Selector,
    /// An advice columns that acts as a selector for prod's gates.
    /// `Out.prod`
    s_prod: Column<Advice>,

    a: Column<Advice>,
    b: Column<Advice>,
    c: Column<Advice>,
    d: Column<Advice>,
}

impl<const WORD_BITS: u32> ProdConfig<WORD_BITS> {
    pub fn new(
        s_table: Selector,
        s_prod: Column<Advice>,

        a: Column<Advice>,
        b: Column<Advice>,
        c: Column<Advice>,
        d: Column<Advice>,
    ) -> Self {
        Self {
            s_table,
            s_prod,
            a,
            b,
            c,
            d,
        }
    }

    pub fn configure<F: FieldExt>(
        meta: &mut impl ConstraintSys<F, Column<Advice>>,
        s_table: Selector,
        s_prod: Column<Advice>,

        a: Column<Advice>,
        b: Column<Advice>,
        c: Column<Advice>,
        d: Column<Advice>,
    ) -> Self {
        let conf @ Self {
            s_table,
            s_prod,
            a,
            b,
            c,
            d,
        } = Self::new(s_table, s_prod, a, b, c, d);

        meta.cs().create_gate("prod", |meta| {
            let max = Expression::Constant(F::from_u128(2u128.pow(WORD_BITS)));

            let s_table = meta.query_selector(s_table);
            let s_prod = meta.query_advice(s_prod, Rotation::cur());

            let a = meta.query_advice(a, Rotation::cur());
            let b = meta.query_advice(b, Rotation::cur());
            let c = meta.query_advice(c, Rotation::cur());
            let d = meta.query_advice(d, Rotation::cur());

            Constraints::with_selector(s_table * s_prod, [a * b - d - max * c])
        });

        conf
    }
}
