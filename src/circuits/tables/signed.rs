use crate::assign::ConstraintSys;
use crate::trace::get_word_size_bit_mask_msb;
use halo2_proofs::circuit::Region;
use halo2_proofs::plonk::Constraints;
use halo2_proofs::{
    arithmetic::FieldExt,
    plonk::{
        Advice, Column, Expression,
        Selector,
    },
    poly::Rotation,
};

use super::even_bits::EvenBitsConfig;

#[derive(Debug, Clone, Copy)]
pub struct SignedConfig<const WORD_BITS: u32> {
    /// A Selector denoting the extent of the exe table.
    s_table: Selector,
    /// An advice columns that acts as a selector for Annd's gates.
    /// `Out.and`
    s_signed: Column<Advice>,

    word: EvenBitsConfig<WORD_BITS>,
    /// Denoted σ_column in the paper.
    msb: Column<Advice>,
    word_sigma: Column<Advice>,
}

impl<const WORD_BITS: u32> SignedConfig<WORD_BITS> {
    pub fn new<F: FieldExt>(
        meta: &mut impl ConstraintSys<F, Column<Advice>>,
        s_table: Selector,
        s_signed: Column<Advice>,
        word: EvenBitsConfig<WORD_BITS>,
    ) -> Self {
        let msb = meta.new_column();
        let word_sigma = meta.new_column();
        Self {
            s_table,
            s_signed,
            word,
            msb,
            word_sigma,
        }
    }

    pub fn configure<F: FieldExt>(
        meta: &mut impl ConstraintSys<F, Column<Advice>>,
        s_table: Selector,
        s_signed: Column<Advice>,
        word: EvenBitsConfig<WORD_BITS>,
    ) -> Self {
        let conf @ Self {
            s_table,
            s_signed,
            word,
            msb,
            word_sigma: _,
        } = Self::new(meta, s_table, s_signed, word);

        meta.cs().create_gate("sum", |meta| {
            let s_table = meta.query_selector(s_table);
            let s_signed = meta.query_advice(s_signed, Rotation::cur());

            let word_odd = meta.query_advice(word.odd, Rotation::cur());
            let msb = meta.query_advice(msb, Rotation::cur());

            let one = Expression::Constant(F::one());
            let two = Expression::Constant(F::from_u128(2));
            Constraints::with_selector(
                s_table * s_signed,
                [word_odd
                    + (one - (two * msb)) * F::from_u128(2u128.pow(WORD_BITS - 2))],
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
        let msb = get_word_size_bit_mask_msb::<WORD_BITS>() & word;

        region
            .assign_advice(|| "msb", self.msb, offset, || Ok(F::from_u128(msb)))
            .unwrap();

        // See page 28
        let word_sigma =
            u128::try_from(-(msb as i128) * 2 * WORD_BITS as i128 + word as i128)
                .unwrap();

        region
            .assign_advice(
                || "word_sigma",
                self.word_sigma,
                offset,
                || Ok(F::from_u128(word_sigma)),
            )
            .unwrap();
    }
}
