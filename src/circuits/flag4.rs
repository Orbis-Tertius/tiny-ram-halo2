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

use super::tables::signed::SignedConfig;

#[derive(Debug, Clone, Copy)]
pub struct Flag4Config<const WORD_BITS: u32> {
    /// A Selector denoting the extent of the exe table.
    s_table: Selector,
    /// An advice columns that acts as a selector for flag4's gate.
    /// [`Out.flag4`](crate::circuits::tables::aux::Out)
    s_flag4: Column<Advice>,

    signed_b: SignedConfig<WORD_BITS>,
    // ρb in the paper
    lsb_b: Column<Advice>,
    b_flag: Column<Advice>,
    flag: Column<Advice>,
}

impl<const WORD_BITS: u32> Flag4Config<WORD_BITS> {
    pub fn configure<F: FieldExt>(
        meta: &mut impl ConstraintSys<F, Column<Advice>>,
        s_table: Selector,
        s_flag4: Column<Advice>,

        signed_b: SignedConfig<WORD_BITS>,
        lsb_b: Column<Advice>,
        b_flag: Column<Advice>,
        flag: Column<Advice>,
    ) -> Self {
        meta.cs().create_gate("flag4", |meta| {
            let one = Expression::Constant(F::one());

            let s_table = meta.query_selector(s_table);
            let s_flag4 = meta.query_advice(s_flag4, Rotation::cur());

            let b_flag = meta.query_advice(b_flag, Rotation::cur());
            let msb_b = meta.query_advice(signed_b.msb, Rotation::cur());
            let lsb_b = meta.query_advice(lsb_b, Rotation::cur());
            let flag_n = meta.query_advice(flag, Rotation::next());

            Constraints::with_selector(
                s_table * s_flag4,
                [flag_n - (b_flag.clone() * msb_b) - ((one - b_flag) * lsb_b)],
            )
        });

        Self {
            s_table,
            s_flag4,
            signed_b,
            lsb_b,
            b_flag,
            flag,
        }
    }

    // TODO remove `left_shift: bool,`
    pub fn assign_flag4<F: FieldExt>(
        &self,
        region: &mut Region<'_, F>,
        b: u64,
        left_shift: bool,
        offset: usize,
    ) {
        let lsb_b = F::from(b & 1);
        region
            .assign_advice(|| "lsb_b", self.lsb_b, offset, || Value::known(lsb_b))
            .unwrap();

        region
            .assign_advice(
                || "b_flag",
                self.b_flag,
                offset,
                || Value::known(F::from(left_shift)),
            )
            .unwrap();
        self.signed_b.assign_signed(region, b.into(), offset);
    }
}
