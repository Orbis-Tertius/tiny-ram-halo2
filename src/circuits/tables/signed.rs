use crate::assign::ConstraintSys;
use crate::trace::get_word_size_bit_mask_msb;
use halo2_proofs::circuit::Region;
use halo2_proofs::plonk::{Constraints, VirtualCells};
use halo2_proofs::{
    arithmetic::FieldExt,
    plonk::{Advice, Column, Expression, Selector},
    poly::Rotation,
};

use super::even_bits::EvenBitsConfig;

#[derive(Debug, Clone, Copy)]
pub struct SignedConfig<const WORD_BITS: u32> {
    /// A Selector denoting the extent of the exe table.
    pub s_table: Selector,
    pub word: EvenBitsConfig<WORD_BITS>,
    /// Denoted σ_column in the paper.
    pub msb: Column<Advice>,
    pub word_sigma: Column<Advice>,
}

impl<const WORD_BITS: u32> SignedConfig<WORD_BITS> {
    pub fn new<F: FieldExt>(
        meta: &mut impl ConstraintSys<F, Column<Advice>>,
        s_table: Selector,
        word: EvenBitsConfig<WORD_BITS>,
    ) -> Self {
        let msb = meta.new_column();
        let word_sigma = meta.new_column();
        Self {
            s_table,
            word,
            msb,
            word_sigma,
        }
    }

    pub fn configure<F: FieldExt>(
        meta: &mut impl ConstraintSys<F, Column<Advice>>,
        s_table: Selector,
        s_signed: impl Fn(&mut VirtualCells<F>) -> Expression<F>,
        word: EvenBitsConfig<WORD_BITS>,
    ) -> Self {
        let conf @ Self {
            s_table,
            word,
            msb,
            // Don't we need to constrain word_sigma?
            word_sigma: _,
        } = Self::new(meta, s_table, word);

        meta.cs().create_gate("signed", |meta| {
            let s_table = meta.query_selector(s_table);
            let s_signed = s_signed(meta);

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
        let word_sigma = -(msb as i128) * 2i128.pow(WORD_BITS) + word as i128;
        let word_sigma = if word_sigma > 0 {
            word_sigma as u128
        } else {
            (2i128.pow(WORD_BITS) + word_sigma) as u128
        };

        eprintln!("word_σ: {}, word: {}", word_sigma, word);
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
