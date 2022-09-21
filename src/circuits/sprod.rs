use crate::assign::ConstraintSys;
use halo2_proofs::circuit::Region;
use halo2_proofs::plonk::{Constraints, Expression};
use halo2_proofs::poly::Rotation;
use halo2_proofs::{
    arithmetic::FieldExt,
    plonk::{Advice, Column, Selector},
};

use super::tables::signed::SignedConfig;

#[derive(Debug, Clone, Copy)]
pub struct SProdConfig<const WORD_BITS: u32> {
    /// A Selector denoting the extent of the exe table.
    s_table: Selector,
    /// An advice columns that acts as a selector for sprod's gates.
    /// `Out.sprod`
    s_sprod: Column<Advice>,

    a: SignedConfig<WORD_BITS>,
    b: SignedConfig<WORD_BITS>,
    c: SignedConfig<WORD_BITS>,
    d: Column<Advice>,
}

impl<const WORD_BITS: u32> SProdConfig<WORD_BITS> {
    pub fn new(
        s_table: Selector,
        s_sprod: Column<Advice>,

        a: SignedConfig<WORD_BITS>,
        b: SignedConfig<WORD_BITS>,
        c: SignedConfig<WORD_BITS>,
        d: Column<Advice>,
    ) -> Self {
        Self {
            s_table,
            s_sprod,
            a,
            b,
            c,
            d,
        }
    }

    pub fn configure<F: FieldExt>(
        meta: &mut impl ConstraintSys<F, Column<Advice>>,
        s_table: Selector,
        s_sprod: Column<Advice>,

        a: SignedConfig<WORD_BITS>,
        b: SignedConfig<WORD_BITS>,
        c: SignedConfig<WORD_BITS>,
        d: Column<Advice>,
    ) -> Self {
        let conf @ Self {
            s_table,
            s_sprod,
            a,
            b,
            c,
            d,
        } = Self::new(s_table, s_sprod, a, b, c, d);

        meta.cs().create_gate("sprod", |meta| {
            let two = Expression::Constant(F::from_u128(2));
            let max = Expression::Constant(F::from_u128(2u128.pow(WORD_BITS)));

            let s_table = meta.query_selector(s_table);
            let s_sprod = meta.query_advice(s_sprod, Rotation::cur());

            let a_sigma = meta.query_advice(a.word_sigma, Rotation::cur());
            let a_msb = meta.query_advice(a.msb, Rotation::cur());
            let a_sigma = -a_msb * two.clone() * a_sigma.clone() + a_sigma;

            let b_sigma = meta.query_advice(b.word_sigma, Rotation::cur());
            let b_msb = meta.query_advice(b.msb, Rotation::cur());
            let b_sigma = -b_msb * two.clone() * b_sigma.clone() + b_sigma;

            let c_sigma = meta.query_advice(c.word_sigma, Rotation::cur());
            let c_msb = meta.query_advice(c.msb, Rotation::cur());
            let c_sigma = -c_msb * two * c_sigma.clone() + c_sigma;

            let d = meta.query_advice(d, Rotation::cur());

            Constraints::with_selector(
                s_table * s_sprod,
                [a_sigma * b_sigma - d - max * c_sigma],
            )
        });

        conf
    }

    pub fn assign_sprod<F: FieldExt>(
        &self,
        region: &mut Region<'_, F>,
        a: F,
        b: F,
        c: F,
        offset: usize,
    ) {
        self.a.assign_signed(region, a.get_lower_128(), offset);

        self.b.assign_signed(region, b.get_lower_128(), offset);
        self.b.word.assign_decompose(region, b, offset);

        self.c.assign_signed(region, c.get_lower_128(), offset);
        self.c.word.assign_decompose(region, c, offset);
    }
}
