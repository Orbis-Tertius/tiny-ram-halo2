use crate::assign::ConstraintSys;
use halo2_proofs::circuit::{Region, Value};
use halo2_proofs::plonk::{Constraints, VirtualCells};
use halo2_proofs::{
    arithmetic::FieldExt,
    plonk::{Advice, Column, Expression, Selector},
    poly::Rotation,
};

use super::even_bits::{EvenBitsConfig, EvenBitsTable};

#[derive(Debug, Clone, Copy)]
pub struct SignedConfig<const WORD_BITS: u32> {
    /// A Selector denoting the extent of the exe table.
    pub s_table: Selector,
    pub word: EvenBitsConfig<WORD_BITS>,
    /// Denoted σ_column in the paper.
    pub msb: Column<Advice>,
    pub word_sigma: Column<Advice>,
    pub check_sign: EvenBitsConfig<WORD_BITS>,
}

impl<const WORD_BITS: u32> SignedConfig<WORD_BITS> {
    pub fn new<F: FieldExt>(
        meta: &mut impl ConstraintSys<F, Column<Advice>>,
        s_table: Selector,
        s_signed: &[Column<Advice>],
        word: EvenBitsConfig<WORD_BITS>,
        even_bits: EvenBitsTable<WORD_BITS>,
    ) -> Self {
        let msb = meta.new_column();
        let word_sigma = meta.new_column();

        let check_sign_exp = meta.new_column();
        let check_sign = EvenBitsConfig::configure(
            meta,
            check_sign_exp,
            s_signed,
            s_table,
            even_bits,
        );
        Self {
            s_table,
            word,
            msb,
            word_sigma,
            check_sign,
        }
    }

    pub fn configure<F: FieldExt>(
        meta: &mut impl ConstraintSys<F, Column<Advice>>,
        s_table: Selector,
        s_signed: &[Column<Advice>],
        word: EvenBitsConfig<WORD_BITS>,
        even_bits: EvenBitsTable<WORD_BITS>,
    ) -> Self {
        let conf @ Self {
            s_table,
            word,
            msb,
            // Don't we need to constrain word_sigma?
            word_sigma,
            check_sign,
        } = Self::new(meta, s_table, s_signed, word, even_bits);

        let s_signed = |meta: &mut VirtualCells<F>| -> Expression<F> {
            let s_table = meta.query_selector(s_table);
            s_signed
                .iter()
                .map(|c| meta.query_advice(*c, Rotation::cur()))
                .fold(None, |e, c| {
                    e.map(|e| Some(e + c.clone())).unwrap_or(Some(c))
                })
                .map(|e| s_table.clone() * (e))
                .unwrap_or(s_table)
        };

        meta.cs().create_gate("signed", |meta| {
            let one = Expression::Constant(F::one());
            let two = Expression::Constant(F::from_u128(2));
            let max = Expression::Constant(F::from_u128(2u128.pow(WORD_BITS)));

            let word_odd = meta.query_advice(word.odd, Rotation::cur());
            let msb = meta.query_advice(msb, Rotation::cur());
            let word_sigma = meta.query_advice(word_sigma, Rotation::cur());
            let word_sigma =
                -msb.clone() * two.clone() * word_sigma.clone() + word_sigma;

            let word = meta.query_advice(word.word, Rotation::cur());
            let check_sign = meta.query_advice(check_sign.word, Rotation::cur());

            // TODO Do we need to range check this?
            Constraints::with_selector(
                s_signed(meta),
                [
                    (-msb.clone() * max + word) - word_sigma,
                    (word_odd
                        + (one - two * msb)
                            * Expression::Constant(F::from(
                                2u64.pow(WORD_BITS - 2),
                            ))
                        - check_sign),
                ],
            )
        });

        conf
    }

    pub fn assign_signed<F: FieldExt>(
        &self,
        region: &mut Region<'_, F>,
        word: u128,
        offset: usize,
    ) {
        let msb = (word >> (WORD_BITS - 1)) & 1;

        region
            .assign_advice(
                || "msb",
                self.msb,
                offset,
                || Value::known(F::from_u128(msb)),
            )
            .unwrap();

        // TODO revist this, compare this approach to using `-F::from(n)`;
        // See page 28
        let word_sigma = -(msb as i128) * 2i128.pow(WORD_BITS) + word as i128;
        let word_sigma = if word_sigma >= 0 {
            word_sigma as u128
        } else {
            -word_sigma as u128
        };

        region
            .assign_advice(
                || "word_sigma",
                self.word_sigma,
                offset,
                || Value::known(F::from_u128(word_sigma)),
            )
            .unwrap();

        let (_e, o) = self
            .word
            .assign_decompose(region, F::from_u128(word), offset);

        let cs = (o.0.get_lower_128() as i128)
            + (1 - 2 * (msb as i128)) * 2i128.pow(WORD_BITS - 2);
        assert!(cs >= 0);
        let cs = F::from_u128(cs as u128);

        self.check_sign.assign_decompose(region, cs, offset);
        region
            .assign_advice(
                || "check_sign",
                self.check_sign.word,
                offset,
                || Value::known(cs),
            )
            .unwrap();
    }
}
