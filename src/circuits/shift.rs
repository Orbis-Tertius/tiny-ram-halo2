use crate::assign::ConstraintSys;
use halo2_proofs::circuit::Value;
use halo2_proofs::pasta::Fp;
use halo2_proofs::plonk::Constraints;
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Chip, Layouter, SimpleFloorPlanner},
    plonk::{
        Advice, Circuit, Column, ConstraintSystem, Error, Expression, Instance,
        Selector,
    },
    poly::Rotation,
};
use std::marker::PhantomData;

use super::tables::even_bits::{EvenBitsConfig, EvenBitsTable};
use super::tables::pow::PowTable;

#[derive(Debug, Clone, Copy)]
pub struct ShiftConfig<const WORD_BITS: u32> {
    /// A Selector denoting the extent of the exe table.
    s_table: Selector,
    /// An advice columns that acts as a selector for shift's gate.
    /// [`Out.shift`](crate::circuits::tables::aux::Out)
    s_shift: Column<Advice>,

    a: Column<Advice>,
    b: Column<Advice>,
    c: Column<Advice>,
    d: Column<Advice>,

    flag: Column<Advice>,

    b_decompose: EvenBitsConfig<WORD_BITS>,

    a_shift: Column<Advice>,
    a_power: Column<Advice>,

    pow: PowTable<WORD_BITS>,
}

impl<const WORD_BITS: u32> ShiftConfig<WORD_BITS> {
    pub fn new(
        s_table: Selector,
        s_shift: Column<Advice>,

        a: Column<Advice>,
        b: Column<Advice>,
        c: Column<Advice>,
        d: Column<Advice>,

        flag: Column<Advice>,

        b_decompose: EvenBitsConfig<WORD_BITS>,

        a_shift: Column<Advice>,
        a_power: Column<Advice>,

        pow: PowTable<WORD_BITS>,
    ) -> Self {
        Self {
            s_table,
            s_shift,
            a,
            b,
            c,
            d,
            flag,
            b_decompose,
            a_shift,
            a_power,
            pow,
        }
    }

    pub fn configure<F: FieldExt>(
        meta: &mut impl ConstraintSys<F, Column<Advice>>,
        s_table: Selector,
        s_shift: Column<Advice>,

        a: Column<Advice>,
        b: Column<Advice>,
        c: Column<Advice>,
        d: Column<Advice>,

        flag: Column<Advice>,

        b_decompose: EvenBitsConfig<WORD_BITS>,

        a_shift: Column<Advice>,
        a_power: Column<Advice>,

        pow: PowTable<WORD_BITS>,
    ) -> Self {
        let conf @ Self {
            s_table,
            s_shift,
            a,
            b,
            c,
            d,
            flag,
            b_decompose,
            a_shift,
            a_power,
            pow,
        } = Self::new(
            s_table,
            s_shift,
            a,
            b,
            c,
            d,
            flag,
            b_decompose,
            a_shift,
            a_power,
            pow,
        );

        meta.cs().create_gate("shift", |meta| {
            let one = Expression::Constant(F::one());
            let two = Expression::Constant(F::from(2));
            let word_bits = Expression::Constant(F::from(WORD_BITS as u64));

            let s_table = meta.query_selector(s_table);
            let s_shift = meta.query_advice(s_shift, Rotation::cur());

            let a = meta.query_advice(a, Rotation::cur());
            let b = meta.query_advice(b, Rotation::cur());
            let c = meta.query_advice(c, Rotation::cur());
            let d = meta.query_advice(d, Rotation::cur());

            let b_o = meta.query_advice(b_decompose.odd, Rotation::cur());
            let b_e = meta.query_advice(b_decompose.even, Rotation::cur());

            let a_shift = meta.query_advice(a_shift, Rotation::cur());
            let a_power = meta.query_advice(a_power, Rotation::cur());

            Constraints::with_selector(
                s_table * s_shift,
                [
                    a_shift.clone() * (a_shift.clone() - one.clone()),
                    (one - a_shift.clone()) * (word_bits - a - (two * b_o) - b_e),
                ],
            )
        });

        let _ = meta.cs().lookup(|meta| {
            let one = Expression::Constant(F::one());
            let two = Expression::Constant(F::from(2));
            let word_bits = Expression::Constant(F::from(WORD_BITS as u64));

            let s_table = meta.query_selector(s_table);
            let s_shift = meta.query_advice(s_shift, Rotation::cur());

            let a = meta.query_advice(a, Rotation::cur());
            let b = meta.query_advice(b, Rotation::cur());
            let c = meta.query_advice(c, Rotation::cur());
            let d = meta.query_advice(d, Rotation::cur());

            let b_o = meta.query_advice(b_decompose.odd, Rotation::cur());
            let b_e = meta.query_advice(b_decompose.even, Rotation::cur());

            let a_shift = meta.query_advice(a_shift, Rotation::cur());
            let a_power = meta.query_advice(a_power, Rotation::cur());

            vec![
                (a.clone() + a_shift * (word_bits - a), pow.values),
                (a_power, pow.powers),
            ]
        });

        conf
    }
}

impl<F: FieldExt, const WORD_BITS: u32> ShiftChip<F, WORD_BITS> {
    pub fn construct(config: <Self as Chip<F>>::Config) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }
}

/// The chip that will implement our instructions! Chips store their own
/// config, as well as type markers if necessary.
pub struct ShiftChip<F: FieldExt, const WORD_BITS: u32> {
    config: ShiftConfig<WORD_BITS>,
    _marker: PhantomData<F>,
}

impl<F: FieldExt, const WORD_BITS: u32> Chip<F> for ShiftChip<F, WORD_BITS> {
    type Config = ShiftConfig<WORD_BITS>;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

#[derive(Default, Debug, Clone, Copy)]
pub struct ShiftCircuit<F: FieldExt, const WORD_BITS: u32> {
    pub a: Option<F>,
    pub b: Option<F>,
}

impl<const WORD_BITS: u32> Circuit<Fp> for ShiftCircuit<Fp, WORD_BITS> {
    type Config = (ShiftConfig<WORD_BITS>, Column<Instance>);
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        let instance = meta.instance_column();
        meta.enable_equality(instance);

        let s_table = meta.complex_selector();
        let s_shift = meta.advice_column();

        let a = meta.advice_column();
        let b = meta.advice_column();
        let c = meta.advice_column();
        meta.enable_equality(c);
        let d = meta.advice_column();

        // Overflow flag
        let flag = meta.advice_column();
        meta.enable_equality(flag);

        let even_bits = EvenBitsTable::new(meta);
        let b_decompose =
            EvenBitsConfig::configure(meta, b, &[s_shift], s_table, even_bits);

        let a_shift = meta.advice_column();
        let a_power = meta.advice_column();

        let pow = PowTable::new(meta);

        (
            ShiftConfig::<WORD_BITS>::configure(
                meta,
                s_table,
                s_shift,
                a,
                b,
                c,
                d,
                flag,
                b_decompose,
                a_shift,
                a_power,
                pow,
            ),
            instance,
        )
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        layouter
            .assign_region(
                || "shift",
                |mut region| {
                    config.0.s_table.enable(&mut region, 0).unwrap();
                    region
                        .assign_advice(
                            || "s_shift",
                            config.0.s_shift,
                            0,
                            || Value::known(Fp::one()),
                        )
                        .unwrap();

                    // If a or b is None then we will see the error early.
                    if self.a.is_some() || self.b.is_some() {
                        // load private
                        let a = self.a.unwrap();
                        let b = self.b.unwrap();

                        region
                            .assign_advice(|| "a", config.0.a, 0, || Value::known(a))
                            .unwrap();
                        region
                            .assign_advice(|| "b", config.0.b, 0, || Value::known(b))
                            .unwrap();
                        region
                            .assign_advice(
                                || "d",
                                config.0.d,
                                0,
                                || Value::known(Fp::zero()),
                            )
                            .unwrap();

                        region
                            .assign_advice(
                                || "fill for the mock prover",
                                config.0.flag,
                                0,
                                || Value::known(Fp::zero()),
                            )
                            .unwrap();
                    }

                    region
                        .assign_advice_from_instance(
                            || "res/c",
                            config.1,
                            0,
                            config.0.c,
                            0,
                        )
                        .unwrap();

                    region
                        .assign_advice_from_instance(
                            || "flag",
                            config.1,
                            1,
                            config.0.flag,
                            1,
                        )
                        .unwrap();

                    Ok(())
                },
            )
            .unwrap();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::*;
    use halo2_proofs::dev::MockProver;
    use proptest::prelude::*;

    prop_compose! {
      fn valid_values(word_bits: u32)
              (a in 0..2u64.pow(word_bits), b in 0..2u64.pow(word_bits))
              -> (u64, u64, u64, bool) {
        let c = a + b;
        let max = 2u64.pow(word_bits);
        let (c, flag) = if c >= max  {
            (c - max, true)
        } else {
            (c, false)
        };

        (a, b, c, flag)
      }
    }

    fn shift<const WORD_BITS: u32>(
        v: Vec<(u64, u64, u64, bool)>,
    ) -> Vec<(ShiftCircuit<Fp, WORD_BITS>, Vec<Vec<Fp>>)> {
        v.into_iter()
            .map(|(a, b, c, flag)| {
                (
                    ShiftCircuit {
                        a: Some(a.into()),
                        b: Some(b.into()),
                    },
                    vec![vec![c.into(), flag.into()]],
                )
            })
            .collect()
    }

    proptest! {
        #[test]
        fn fp_u128_test(n in 0..u128::MAX) {
            let a = Fp::from_u128(n);
            let b = a.get_lower_128();
            assert_eq!(b, n)
        }

        /// proptest does not support testing const generics.
        #[test]
        fn all_8_bit_words_mock_prover_test((a, b, c, flag) in valid_values(8)) {
            mock_prover_test::<8>(a, b, c, flag)
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig {
          cases: 20, .. ProptestConfig::default()
        })]

        #[test]
        fn all_8_bit_words_test(s in prop::collection::vec(valid_values(8), 10)) {
            gen_proofs_and_verify::<8, _>(shift::<8>(s))
        }

        #[test]
        fn all_16_bit_words_mock_prover_test((a, b, c, flag) in valid_values(16)) {
            mock_prover_test::<16>(a, b, c, flag)
        }

        #[test]
        fn all_16_bit_words_test(s in prop::collection::vec(valid_values(16), 10)) {
            gen_proofs_and_verify::<16, _>(shift::<16>(s))
        }

        #[test]
        fn all_8_bit_words_test_bad_proof(a in 0..2u64.pow(8), b in 0..2u64.pow(8), c in 0..2u64.pow(8), flag: bool) {
            let overflow_correct = flag && (a + b).checked_sub(2u64.pow(8)).map(|s| c == s).unwrap_or(false);
            prop_assume!((c != a + b));
            prop_assume!(!overflow_correct);
            let circuit = ShiftCircuit::<Fp, 8> {a: Some(a.into()), b: Some(b.into())};
            gen_proofs_and_verify_should_fail::<8, _>(circuit, vec![c.into(), flag.into()])
        }
    }

    proptest! {
        // The case number was picked to run all tests in about 60 seconds on my machine.
        // TODO use `plonk::BatchVerifier` to speed up tests.
        #![proptest_config(ProptestConfig {
          cases: 10, .. ProptestConfig::default()
        })]

        #[test]
        fn all_24_bit_words_mock_prover_test((a, b, c, flag) in valid_values(24)) {
            mock_prover_test::<24>(a, b, c, flag)
        }

        #[test]
        fn all_24_bit_words_test(s in prop::collection::vec(valid_values(24), 10)) {
            gen_proofs_and_verify::<24, _>(shift::<24>(s))
        }
    }

    // It's used in the proptests
    fn mock_prover_test<const WORD_BITS: u32>(a: u64, b: u64, c: u64, flag: bool) {
        let k = 1 + WORD_BITS / 2;
        let circuit: ShiftCircuit<Fp, WORD_BITS> = ShiftCircuit {
            a: Some(Fp::from(a)),
            b: Some(Fp::from(b)),
        };

        let prover =
            MockProver::run(k, &circuit, vec![vec![c.into(), flag.into()]]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }
}
