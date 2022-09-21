// TODO add tests using dead code
#![allow(dead_code)]
use crate::assign::ConstraintSys;
use halo2_proofs::circuit::{Region, Value};
use halo2_proofs::plonk::{Constraints, Expression};
use halo2_proofs::{
    arithmetic::FieldExt,
    plonk::{Advice, Column, Selector},
    poly::Rotation,
};

use super::tables::even_bits::EvenBitsConfig;

#[derive(Debug, Clone, Copy)]
pub struct Flag3Config<const WORD_BITS: u32> {
    /// A Selector denoting the extent of the exe table.
    s_table: Selector,
    /// An advice columns that acts as a selector for flag3's gate.
    /// [`Out.flag3`](crate::circuits::tables::aux::Out)
    s_flag3: Column<Advice>,

    a: Column<Advice>,
    b: Column<Advice>,
    c: Column<Advice>,
    flag: Column<Advice>,

    r: EvenBitsConfig<WORD_BITS>,
}

impl<const WORD_BITS: u32> Flag3Config<WORD_BITS> {
    #[allow(clippy::complexity)]
    pub fn configure<F: FieldExt>(
        meta: &mut impl ConstraintSys<F, Column<Advice>>,
        s_table: Selector,
        s_flag3: Column<Advice>,

        a: Column<Advice>,
        b: Column<Advice>,
        c: Column<Advice>,
        flag: Column<Advice>,
        r: EvenBitsConfig<WORD_BITS>,
    ) -> Self {
        meta.cs().create_gate("flag3", |meta| {
            let one = Expression::Constant(F::one());
            let two = Expression::Constant(F::from(2));

            let s_table = meta.query_selector(s_table);
            let s_flag3 = meta.query_advice(s_flag3, Rotation::cur());

            let a = meta.query_advice(a, Rotation::cur());
            let b = meta.query_advice(b, Rotation::cur());
            let c = meta.query_advice(c, Rotation::cur());

            let flag_n = meta.query_advice(flag, Rotation::next());

            let re = meta.query_advice(r.even, Rotation::cur());
            let ro = meta.query_advice(r.odd, Rotation::cur());
            let r = meta.query_advice(r.word, Rotation::cur());

            // page 29
            Constraints::with_selector(
                s_table * s_flag3,
                [
                    b * flag_n.clone()
                        + (one.clone() - flag_n)
                            * (c.clone() - a.clone() - one.clone() - two * ro - re),
                    // This is just to ensure the r decompose is correct.
                    // We should experiment with decompose taking an expression rather
                    // than a column. This would make decompose gates less reusable, but
                    // might save a column in a few cases.
                    //
                    // Otherwise we should replace `c - a - one` in the constraint above with r.

                    // r is only defined for c != 0.  (page 29)
                    c.clone() * ((c - a - one) - r),
                ],
            )
        });

        Self {
            s_table,
            s_flag3,
            c,
            flag,
            a,
            b,
            r,
        }
    }

    pub fn assign_flag3<F: FieldExt>(
        &self,
        region: &mut Region<'_, F>,
        a: F,
        c: F,
        offset: usize,
    ) {
        // Used to prove `a < c` when c != 0.
        let r = if c == F::zero() {
            F::zero()
        } else {
            c - a - F::one()
        };
        region
            .assign_advice(|| "r", self.r.word, offset, || Value::known(r))
            .unwrap();
        self.r.assign_decompose(region, r, offset);
    }
}
