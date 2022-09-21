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

#[derive(Debug, Clone, Copy)]
pub struct SumConfig<const WORD_BITS: u32> {
    /// A Selector denoting the extent of the exe table.
    s_table: Selector,
    /// An advice columns that acts as a selector for sum's gate.
    /// [`Out.sum`](crate::circuits::tables::aux::Out)
    pub s_sum: Column<Advice>,

    a: Column<Advice>,
    b: Column<Advice>,
    c: Column<Advice>,
    d: Column<Advice>,

    flag: Column<Advice>,
}

impl<const WORD_BITS: u32> SumConfig<WORD_BITS> {
    pub fn new(
        s_table: Selector,
        s_sum: Column<Advice>,

        a: Column<Advice>,
        b: Column<Advice>,
        c: Column<Advice>,
        d: Column<Advice>,

        flag: Column<Advice>,
    ) -> Self {
        Self {
            s_table,
            s_sum,
            a,
            b,
            c,
            d,
            flag,
        }
    }

    #[allow(clippy::complexity)]
    pub fn configure<F: FieldExt>(
        meta: &mut impl ConstraintSys<F, Column<Advice>>,
        s_table: Selector,
        s_sum: Column<Advice>,

        a: Column<Advice>,
        b: Column<Advice>,
        c: Column<Advice>,
        d: Column<Advice>,

        flag: Column<Advice>,
    ) -> Self {
        let conf @ Self {
            s_table,
            s_sum,
            a,
            b,
            c,
            d,
            flag,
        } = Self::new(s_table, s_sum, a, b, c, d, flag);

        meta.cs().create_gate("sum", |meta| {
            let s_table = meta.query_selector(s_table);
            let s_sum = meta.query_advice(s_sum, Rotation::cur());

            let a = meta.query_advice(a, Rotation::cur());
            let b = meta.query_advice(b, Rotation::cur());
            let c = meta.query_advice(c, Rotation::cur());
            let d = meta.query_advice(d, Rotation::cur());
            let flag_n = meta.query_advice(flag, Rotation::next());

            Constraints::with_selector(
                s_table * s_sum,
                [a + b
                    - c
                    - (Expression::Constant(F::from_u128(2u128.pow(WORD_BITS)))
                        * flag_n)
                    + d],
            )
        });

        conf
    }
}

impl<F: FieldExt, const WORD_BITS: u32> AndChip<F, WORD_BITS> {
    pub fn construct(config: <Self as Chip<F>>::Config) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }
}

/// The chip that will implement our instructions! Chips store their own
/// config, as well as type markers if necessary.
pub struct AndChip<F: FieldExt, const WORD_BITS: u32> {
    config: SumConfig<WORD_BITS>,
    _marker: PhantomData<F>,
}

impl<F: FieldExt, const WORD_BITS: u32> Chip<F> for AndChip<F, WORD_BITS> {
    type Config = SumConfig<WORD_BITS>;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

#[derive(Default, Debug, Clone, Copy)]
pub struct SumCircuit<F: FieldExt, const WORD_BITS: u32> {
    pub a: Option<F>,
    pub b: Option<F>,
}

impl<const WORD_BITS: u32> Circuit<Fp> for SumCircuit<Fp, WORD_BITS> {
    type Config = (SumConfig<WORD_BITS>, Column<Instance>);
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        let instance = meta.instance_column();
        meta.enable_equality(instance);

        let s_table = meta.complex_selector();
        let s_sum = meta.advice_column();

        let a = meta.advice_column();
        let b = meta.advice_column();
        let c = meta.advice_column();
        meta.enable_equality(c);
        let d = meta.advice_column();

        // Overflow flag
        let flag = meta.advice_column();
        meta.enable_equality(flag);

        (
            SumConfig::<WORD_BITS>::configure(
                meta, s_table, s_sum, a, b, c, d, flag,
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
                || "sum",
                |mut region| {
                    config.0.s_table.enable(&mut region, 0).unwrap();
                    region
                        .assign_advice(
                            || "s_sum",
                            config.0.s_sum,
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

    fn sum<const WORD_BITS: u32>(
        v: Vec<(u64, u64, u64, bool)>,
    ) -> Vec<(SumCircuit<Fp, WORD_BITS>, Vec<Vec<Fp>>)> {
        v.into_iter()
            .map(|(a, b, c, flag)| {
                (
                    SumCircuit {
                        a: Some(a.into()),
                        b: Some(b.into()),
                    },
                    vec![vec![c.into(), flag.into()]],
                )
            })
            .collect()
    }

    proptest! {
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
            gen_proofs_and_verify::<8, _>(sum::<8>(s))
        }

        #[test]
        fn all_16_bit_words_mock_prover_test((a, b, c, flag) in valid_values(16)) {
            mock_prover_test::<16>(a, b, c, flag)
        }

        #[test]
        fn all_16_bit_words_test(s in prop::collection::vec(valid_values(16), 10)) {
            gen_proofs_and_verify::<16, _>(sum::<16>(s))
        }

        #[test]
        fn all_8_bit_words_test_bad_proof(a in 0..2u64.pow(8), b in 0..2u64.pow(8), c in 0..2u64.pow(8), flag: bool) {
            let overflow_correct = flag && (a + b).checked_sub(2u64.pow(8)).map(|s| c == s).unwrap_or(false);
            prop_assume!((c != a + b));
            prop_assume!(!overflow_correct);
            let circuit = SumCircuit::<Fp, 8> {a: Some(a.into()), b: Some(b.into())};
            gen_proofs_and_verify_should_fail::<8, _>(circuit, vec![c.into(), flag.into()])
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig {
          cases: 10, .. ProptestConfig::default()
        })]

        #[test]
        fn all_24_bit_words_mock_prover_test((a, b, c, flag) in valid_values(24)) {
            mock_prover_test::<24>(a, b, c, flag)
        }

        #[test]
        fn all_24_bit_words_test(s in prop::collection::vec(valid_values(24), 10)) {
            gen_proofs_and_verify::<24, _>(sum::<24>(s))
        }
    }

    // It's used in the proptests
    fn mock_prover_test<const WORD_BITS: u32>(a: u64, b: u64, c: u64, flag: bool) {
        let k = 1 + WORD_BITS / 2;
        let circuit: SumCircuit<Fp, WORD_BITS> = SumCircuit {
            a: Some(Fp::from(a)),
            b: Some(Fp::from(b)),
        };

        let prover =
            MockProver::run(k, &circuit, vec![vec![c.into(), flag.into()]]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }
}
