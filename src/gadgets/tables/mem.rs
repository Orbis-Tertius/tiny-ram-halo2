use std::{marker::PhantomData, ops::Deref};

use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{AssignedCell, Chip, Layouter, Region},
    plonk::{Advice, Column, Error, Instance, Selector, TableColumn},
};

pub trait EvenBitsLookup<F: FieldExt>: Chip<F> {
    type Word;

    #[allow(clippy::type_complexity)]
    fn decompose(
        &self,
        layouter: impl Layouter<F>,
        c: Self::Word,
    ) -> Result<(EvenBits<Self::Word>, OddBits<Self::Word>), Error>;
}

/// A newtype of a field element containing only bits
/// that were in the even position of the decomposed element.
/// All odd bits will be zero.
#[derive(Clone, Copy, Debug)]
pub struct EvenBits<W>(pub W);

impl<W> Deref for EvenBits<W> {
    type Target = W;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// A newtype of a field element containing only bits
/// that were in the odd position of the decomposed element.
/// All odd bits will be right shifted by 1 into even positions.
/// All odd bits will be zero.
#[derive(Clone, Copy, Debug)]
pub struct OddBits<W>(pub W);

impl<W> Deref for OddBits<W> {
    type Target = W;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Clone, Debug)]
pub struct EvenBitsChip<F: FieldExt, const WORD_BITS: u32> {
    config: EvenBitsConfig<WORD_BITS>,
    _marker: PhantomData<F>,
}

/// Chip state is stored in a config struct. This is generated by the chip
/// during configuration, and then stored inside the chip.
#[derive(Clone, Debug)]
pub struct EvenBitsConfig<const WORD_BITS: u32> {
    even: Column<Advice>,
    odd: Column<Advice>,

    instance: Column<Instance>,

    even_bits: TableColumn,

    s_decompose: Selector,
}

impl<F: FieldExt, const WORD_BITS: u32> Chip<F> for EvenBitsChip<F, WORD_BITS> {
    type Config = EvenBitsConfig<WORD_BITS>;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

impl<F: FieldExt, const WORD_BITS: u32> EvenBitsLookup<F> for EvenBitsChip<F, WORD_BITS> {
    type Word = AssignedCell<F, F>;

    fn decompose(
        &self,
        mut layouter: impl Layouter<F>,
        c: Self::Word,
    ) -> Result<(EvenBits<Self::Word>, OddBits<Self::Word>), Error> {
        let config = self.config();

        layouter.assign_region(
            || "decompose",
            |mut region: Region<'_, F>| {
                config.s_decompose.enable(&mut region, 0)?;

                let o_oe = c.value().cloned().map(decompose);
                let e_cell = region
                    .assign_advice(
                        || "even bits",
                        config.even,
                        0,
                        || o_oe.map(|oe| *oe.0).ok_or(Error::Synthesis),
                    )
                    .map(EvenBits)?;

                let o_cell = region
                    .assign_advice(
                        || "odd bits",
                        config.odd,
                        0,
                        || o_oe.map(|oe| *oe.1).ok_or(Error::Synthesis),
                    )
                    .map(OddBits)?;

                c.copy_advice(|| "out", &mut region, config.even, 1)?;
                Ok((e_cell, o_cell))
            },
        )
    }
}

fn decompose<F: FieldExt>(word: F) -> (EvenBits<F>, OddBits<F>) {
    assert!(word <= F::from_u128(u128::MAX));

    let mut even_only = word.to_repr();
    even_only.as_mut().iter_mut().for_each(|bits| {
        *bits &= 0b01010101;
    });

    let mut odd_only = word.to_repr();
    odd_only.as_mut().iter_mut().for_each(|bits| {
        *bits &= 0b10101010;
    });

    let even_only = EvenBits(F::from_repr(even_only).unwrap());
    let odd_only = F::from_repr(odd_only).unwrap();
    let odds_in_even = OddBits(F::from_u128(odd_only.get_lower_128() >> 1));
    (even_only, odds_in_even)
}

#[test]
fn decompose_test_even_odd() {
    use pasta_curves::Fp;
    let odds = 0xAAAA;
    let evens = 0x5555;
    let (e, o) = decompose(Fp::from_u128(odds));
    assert_eq!(e.get_lower_128(), 0);
    assert_eq!(o.get_lower_128(), odds >> 1);
    let (e, o) = decompose(Fp::from_u128(evens));
    assert_eq!(e.get_lower_128(), evens);
    assert_eq!(o.get_lower_128(), 0);
}

use proptest::prelude::*;
proptest! {

    #[test]
    fn decompose_test(a in 0..u128::MAX) {
        use pasta_curves::Fp;
        let a = Fp::from_u128(a);
        decompose(a);
    }

    #[test]
    fn fp_u128_test(n in 0..u128::MAX) {
        use pasta_curves::Fp;
        let a = Fp::from_u128(n);
        let b = a.get_lower_128();
        assert_eq!(b, n)
    }
}
