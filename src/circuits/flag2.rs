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
use rand_core::OsRng;

#[derive(Debug, Clone, Copy)]
pub struct Flag2Config<const WORD_BITS: u32> {
    /// A Selector denoting the extent of the exe table.
    s_table: Selector,
    /// An advice columns that acts as a selector for flag2's gate.
    /// [`Out.flag2`](crate::circuits::tables::aux::Out)
    s_flag2: Column<Advice>,

    c: Column<Advice>,
    flag: Column<Advice>,

    // Could we eliminate this column?
    a_flag: Column<Advice>,
}

impl<const WORD_BITS: u32> Flag2Config<WORD_BITS> {
    pub fn configure<F: FieldExt>(
        meta: &mut impl ConstraintSys<F, Column<Advice>>,
        s_table: Selector,
        s_flag2: Column<Advice>,

        c: Column<Advice>,
        flag: Column<Advice>,
        a_flag: Column<Advice>,
    ) -> Self {
        meta.cs().create_gate("flag2", |meta| {
            let s_table = meta.query_selector(s_table);
            let s_flag2 = meta.query_advice(s_flag2, Rotation::cur());

            let c = meta.query_advice(c, Rotation::cur());
            let flag_n = meta.query_advice(flag, Rotation::next());
            let a_flag = meta.query_advice(a_flag, Rotation::cur());

            Constraints::with_selector(
                s_table * s_flag2,
                [(flag_n + c) * a_flag - Expression::Constant(F::one())],
            )
        });

        Self {
            s_table,
            s_flag2,
            c,
            flag,
            a_flag,
        }
    }

    pub fn assign_flag2<F: FieldExt>(
        &self,
        region: &mut Region<'_, F>,
        c: F,
        flag_next: F,
        offset: usize,
    ) {
        // a_flag can be anything when `c + flag_next = 0`.
        // TODO replace with seedable Rng to add back determinism.
        let a_flag = (c + flag_next).invert().unwrap_or(F::random(OsRng));
        region
            .assign_advice(|| "a_flag", self.a_flag, offset, || Value::known(a_flag))
            .unwrap();
    }
}
