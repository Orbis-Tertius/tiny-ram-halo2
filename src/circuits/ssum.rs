use crate::assign::ConstraintSys;
use halo2_proofs::circuit::Region;
use halo2_proofs::plonk::Constraints;
use halo2_proofs::{
    arithmetic::FieldExt,
    plonk::{Advice, Column, Expression, Selector},
    poly::Rotation,
};

use super::tables::signed::SignedConfig;

#[derive(Debug, Clone, Copy)]
pub struct SSumConfig<const WORD_BITS: u32> {
    /// A Selector denoting the extent of the exe table.
    s_table: Selector,
    /// An advice columns that acts as a selector for sum's gates.
    /// `Out.sum`
    s_sum: Column<Advice>,

    a: SignedConfig<WORD_BITS>,
    b: Column<Advice>,
    c: SignedConfig<WORD_BITS>,
    d: Column<Advice>,
    flag: Column<Advice>,
}

impl<const WORD_BITS: u32> SSumConfig<WORD_BITS> {
    pub fn new(
        s_table: Selector,
        s_sum: Column<Advice>,

        a: SignedConfig<WORD_BITS>,
        b: Column<Advice>,
        c: SignedConfig<WORD_BITS>,
        d: Column<Advice>,

        flag: Column<Advice>,
    ) -> Self {
        Self {
            s_table,
            s_sum,
            a,
            b,
            c,
            d,
            flag,
        }
    }

    pub fn configure<F: FieldExt>(
        meta: &mut impl ConstraintSys<F, Column<Advice>>,
        s_table: Selector,
        s_sum: Column<Advice>,

        a: SignedConfig<WORD_BITS>,
        b: Column<Advice>,
        c: SignedConfig<WORD_BITS>,
        d: Column<Advice>,

        flag: Column<Advice>,
    ) -> Self {
        let conf @ Self {
            s_table,
            s_sum,
            a,
            b,
            c,
            d,
            flag,
        } = Self::new(s_table, s_sum, a, b, c, d, flag);

        meta.cs().create_gate("ssum", |meta| {
            let s_table = meta.query_selector(s_table);
            let s_sum = dbg!(meta.query_advice(s_sum, Rotation::cur())); // 1

            let a = dbg!(meta.query_advice(a.word_sigma, Rotation::cur())); // 1
            let b = dbg!(meta.query_advice(b, Rotation::cur())); // 255
            let c = dbg!(meta.query_advice(c.word_sigma, Rotation::cur())); // 255
            let d = dbg!(meta.query_advice(d, Rotation::cur())); // 0
            let flag_n = dbg!(meta.query_advice(flag, Rotation::next())); // 1

            Constraints::with_selector(
                s_table * s_sum,
                [a + b
                    - c
                    - (Expression::Constant(F::from_u128(2u128.pow(WORD_BITS)))
                        * flag_n)
                    + d],
            )
        });

        conf
    }

    pub fn assign_sum<F: FieldExt>(
        &self,
        region: &mut Region<'_, F>,
        a: F,
        c: F,
        offset: usize,
    ) {
        self.a.assign_signed(region, a.get_lower_128(), offset);
        self.c.assign_signed(region, c.get_lower_128(), offset);
        self.c.word.assign_decompose(region, c, offset);
    }
}
