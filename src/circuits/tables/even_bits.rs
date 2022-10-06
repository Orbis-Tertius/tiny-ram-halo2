use std::{marker::PhantomData, ops::Deref};

use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Chip, Layouter, Region, Value},
    plonk::{
        Advice, Column, ConstraintSystem, Error, Expression, Selector, TableColumn,
        VirtualCells,
    },
    poly::Rotation,
};

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

pub trait HasEvenBits<const WORD_BITS: u32> {
    fn even_bits(&self) -> EvenBitsTable<WORD_BITS>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EvenBitsTable<const WORD_BITS: u32>(TableColumn);

impl<const WORD_BITS: u32> EvenBitsTable<WORD_BITS> {
    pub fn new<F: FieldExt>(meta: &mut ConstraintSystem<F>) -> Self {
        Self(meta.lookup_table_column())
    }

    // Allocates all even bits in a a table for the word size WORD_BITS.
    // `2^(WORD_BITS/2)` rows of the constraint system.
    pub fn alloc_table<F: FieldExt>(
        self,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        layouter.assign_table(
            || "even bits",
            |mut table| {
                for i in 0..2usize.pow(WORD_BITS / 2) {
                    table.assign_cell(
                        || format!("even_bits row {}", i),
                        self.0,
                        i,
                        || Value::known(F::from(even_bits_at(i) as u64)),
                    )?;
                }
                Ok(())
            },
        )
    }
}

/// Chip state is stored in a config struct. This is generated by the chip
/// during configuration, and then stored inside the chip.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EvenBitsConfig<const WORD_BITS: u32> {
    pub word: Column<Advice>,
    pub even: Column<Advice>,
    pub odd: Column<Advice>,
    pub even_bits: EvenBitsTable<WORD_BITS>,

    pub s_table: Selector,
}

impl<const WORD_BITS: u32> EvenBitsConfig<WORD_BITS> {
    fn new<F: FieldExt>(
        meta: &mut impl ConstraintSys<F, Column<Advice>>,
        word: Column<Advice>,
        _s_even_bits: &[Column<Advice>],
        // A complex selector denoting the extent in rows of the table to decompse.
        s_table: Selector,
        even_bits: EvenBitsTable<WORD_BITS>,
    ) -> Self {
        let even = meta.new_column();
        let odd = meta.new_column();
        Self {
            word,
            even,
            odd,
            even_bits,
            s_table,
        }
    }

    // `s_even_bits` contains the advice selectors that enable this decomposition.
    // The sum of `s_even_bits` must be 0 or 1.
    //
    // `s_table` denotes the maxium extent of the Exe table.
    //
    // The decomposition is enforced when `s_table * (s_even_bits[0] + s_even_bits[1] + ..)` is 1.
    pub fn configure<F: FieldExt>(
        meta: &mut impl ConstraintSys<F, Column<Advice>>,
        word: Column<Advice>,
        s_even_bits: &[Column<Advice>],
        // A complex selector denoting the extent in rows of the table to decompse.
        s_table: Selector,
        even_bits: EvenBitsTable<WORD_BITS>,
    ) -> Self {
        let conf @ Self {
            word,
            even,
            odd,
            even_bits,
            s_table,
        } = Self::new(meta, word, s_even_bits, s_table, even_bits);

        let meta = meta.cs();

        let s_even_bits = |meta: &mut VirtualCells<F>| -> Expression<F> {
            let s_table = meta.query_selector(s_table);
            s_even_bits
                .iter()
                .map(|c| meta.query_advice(*c, Rotation::cur()))
                .fold(None, |e, c| {
                    // We sum advice selectors, since only one of them can be enabled on each row.
                    e.map(|e| Some(e + c.clone())).unwrap_or(Some(c))
                })
                .map(|e| s_table.clone() * (e))
                .unwrap_or(s_table)
        };

        meta.create_gate("decompose", |meta| {
            let s_even_bits = s_even_bits(meta);
            let lhs = meta.query_advice(even, Rotation::cur());
            let rhs = meta.query_advice(odd, Rotation::cur());
            let out = meta.query_advice(word, Rotation::cur());

            vec![s_even_bits * (lhs + Expression::Constant(F::from(2)) * rhs - out)]
        });

        let _ = meta.lookup(|meta| {
            let s_even_bits = s_even_bits(meta);
            let e = meta.query_advice(even, Rotation::cur());

            vec![(s_even_bits * e, even_bits.0)]
        });

        let _ = meta.lookup(|meta| {
            let s_even_bits = s_even_bits(meta);
            let o = meta.query_advice(odd, Rotation::cur());

            vec![(s_even_bits * o, even_bits.0)]
        });

        conf
    }

    /// Assign the word's even_bits, and the word's odd bits shifted into even positions.
    pub fn assign_decompose<F: FieldExt>(
        &self,
        region: &mut Region<'_, F>,
        word: F,
        offset: usize,
    ) -> (EvenBits<F>, OddBits<F>) {
        let (e, o) = decompose(word);
        let _ = region
            .assign_advice(|| "even bits", self.even, offset, || Value::known(e.0))
            .map(EvenBits)
            .unwrap();

        let _ = region
            .assign_advice(|| "odd bits", self.odd, offset, || Value::known(o.0))
            .map(OddBits)
            .unwrap();
        (e, o)
    }
}

#[derive(Clone, Debug)]
pub struct EvenBitsChip<F: FieldExt, const WORD_BITS: u32> {
    config: EvenBitsConfig<WORD_BITS>,
    _marker: PhantomData<F>,
}

impl<F: FieldExt, const WORD_BITS: u32> EvenBitsChip<F, WORD_BITS> {
    pub fn construct(config: <Self as Chip<F>>::Config) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }
}

fn even_bits_at(mut i: usize) -> usize {
    let mut r = 0;
    let mut c = 0;

    while i != 0 {
        let lower_bit = i % 2;
        r += lower_bit * 4usize.pow(c);
        i >>= 1;
        c += 1;
    }

    r
}

#[test]
fn even_bits_at_test() {
    assert_eq!(0b0, even_bits_at(0));
    assert_eq!(0b1, even_bits_at(1));
    assert_eq!(0b100, even_bits_at(2));
    assert_eq!(0b101, even_bits_at(3));
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

fn decompose<F: FieldExt>(word: F) -> (EvenBits<F>, OddBits<F>) {
    // FIXME re-enable assertion
    // assert!(word <= F::from_u128(u128::MAX));

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
    use halo2_proofs::pasta::Fp;
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

use crate::assign::ConstraintSys;

proptest! {
    #[test]
    fn decompose_test(a in 0..u128::MAX) {
        use halo2_proofs::pasta::Fp;
        let a = Fp::from_u128(a);
        decompose(a);
    }

    #[test]
    fn fp_u128_test(n in 0..u128::MAX) {
        use halo2_proofs::pasta::Fp;
        let a = Fp::from_u128(n);
        let b = a.get_lower_128();
        assert_eq!(b, n)
    }
}

#[cfg(test)]
mod mem_test {
    use halo2_proofs::pasta::Fp;
    use halo2_proofs::{
        circuit::SimpleFloorPlanner, dev::MockProver, plonk::Circuit,
    };

    use super::*;

    // TODO take a look at how they test in src/ecc/chip/mul.rs
    // That looks useful.

    #[derive(Default)]
    pub struct EvenBitsTestCircuit<F: FieldExt, const WORD_BITS: u32 = 8> {
        pub input: Option<F>,
    }

    impl<F: FieldExt, const WORD_BITS: u32> Circuit<F>
        for EvenBitsTestCircuit<F, WORD_BITS>
    {
        // Since we are using a single chip for everything, we can just reuse its config.
        type Config = EvenBitsConfig<WORD_BITS>;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            let word = meta.advice_column();
            let s_table = meta.complex_selector();
            let even_bits = EvenBitsTable::new(meta);

            EvenBitsConfig::<WORD_BITS>::configure(
                meta,
                word,
                &[],
                s_table,
                even_bits,
            )
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            let field_chip = EvenBitsChip::<F, WORD_BITS>::construct(config);
            field_chip
                .config
                .even_bits
                .alloc_table(&mut layouter.namespace(|| "alloc table"))?;

            layouter
                .assign_region(
                    || "decompose",
                    |mut region| {
                        config.s_table.enable(&mut region, 0)?;
                        if let Some(word) = self.input {
                            region
                                .assign_advice(
                                    || "word",
                                    config.word,
                                    0,
                                    || Value::known(word),
                                )
                                .unwrap();
                            config.assign_decompose(&mut region, word, 0);
                        };
                        Ok(())
                    },
                )
                .unwrap();

            Ok(())
        }
    }

    #[allow(unused)]
    fn mock_prover_test<const WORD_BITS: u32>(a: u64) {
        let k = 1 + WORD_BITS / 2;
        let circuit = EvenBitsTestCircuit::<Fp, WORD_BITS> {
            input: Some(Fp::from(a)),
        };

        // Given the correct public input, our circuit will verify.
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

    proptest! {
        // The case number was picked to run all tests in about 60 seconds on my machine.
        #![proptest_config(ProptestConfig {
          cases: 20, .. ProptestConfig::default()
        })]

        #[test]
        fn all_24_bit_words_mock_prover_test(a in 0..2u64.pow(24)) {
            mock_prover_test::<24>(a)
        }

        #[test]
        #[should_panic]
        fn all_24_bit_words_test_bad_proof(a in 2u64.pow(24)..) {
            mock_prover_test::<24>(a)
        }
    }
}
