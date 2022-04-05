use super::tables::even_bits::{EvenBitsChip, EvenBitsConfig, EvenBitsLookup};
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{AssignedCell, Chip, Layouter, Region, SimpleFloorPlanner},
    dev::MockProver,
    plonk::{
        Advice, Circuit, Column, ConstraintSystem, Error, Expression, Fixed,
        Instance, Selector,
    },
    poly::Rotation,
};
use pasta_curves::Fp;
use std::marker::PhantomData;

pub trait GreaterThanInstructions<F: FieldExt>: Chip<F> {
    /// Variable representing a number.
    type Word;

    /// Loads a number into the circuit as a private input.
    fn load_private(
        &self,
        layouter: impl Layouter<F>,
        a: Option<F>,
    ) -> Result<Self::Word, Error>;

    fn greater_than(
        &self,
        layouter: impl Layouter<F>,
        a: Self::Word,
        b: Self::Word,
    ) -> Result<(Self::Word, Self::Word), Error>;

    fn expose_public(
        &self,
        layouter: impl Layouter<F>,
        num: Self::Word,
        row: usize,
    ) -> Result<(), Error>;
}

pub struct GreaterThanChip<F: FieldExt, const WORD_BITS: u32> {
    config: GreaterThanConfig,
    _marker: PhantomData<F>,
}

#[derive(Clone, Debug)]
pub struct GreaterThanConfig {
    advice: [Column<Advice>; 2],
    instance: Column<Instance>,
    s_gt: Selector,
}

impl<F: FieldExt, const WORD_BITS: u32> GreaterThanChip<F, WORD_BITS> {
    fn construct(config: <Self as Chip<F>>::Config) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }

    fn configure(
        meta: &mut ConstraintSystem<F>,
        advice: [Column<Advice>; 2],
        instance: Column<Instance>,
        constant: Column<Fixed>,
    ) -> <Self as Chip<F>>::Config {
        meta.enable_equality(instance);
        meta.enable_constant(constant);
        for column in &advice {
            meta.enable_equality(*column);
        }

        let s_gt = meta.selector();

        meta.create_gate("greater than", |meta| {
            let lhs = meta.query_advice(advice[0], Rotation::cur());
            let rhs = meta.query_advice(advice[1], Rotation::cur());

            // this value is `lhs - rhs` if `lhs !> rhs` and `2^W - (lhs - rhs)` if `lhs > rhs`
            let helper = meta.query_advice(advice[0], Rotation::next());

            let is_greater = meta.query_advice(advice[1], Rotation::next());
            let s_gt = meta.query_selector(s_gt);

            vec![
                s_gt * (lhs - rhs + helper
                    - Expression::Constant(F::from(2_u64.pow(WORD_BITS)))
                        * is_greater),
            ]
        });

        GreaterThanConfig {
            advice,
            instance,
            s_gt,
        }
    }
}

impl<F: FieldExt, const WORD_BITS: u32> Chip<F> for GreaterThanChip<F, WORD_BITS> {
    type Config = GreaterThanConfig;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

/// A variable representing a number.
#[derive(Clone, Debug)]
pub struct Word<F: FieldExt>(AssignedCell<F, F>);

impl<const WORD_BITS: u32> GreaterThanInstructions<Fp>
    for GreaterThanChip<Fp, WORD_BITS>
{
    type Word = Word<Fp>;

    fn load_private(
        &self,
        mut layouter: impl Layouter<Fp>,
        value: Option<Fp>,
    ) -> Result<Self::Word, Error> {
        let config = self.config();

        layouter.assign_region(
            || "load private",
            |mut region| {
                region
                    .assign_advice(
                        || "private input",
                        config.advice[0],
                        0,
                        || value.ok_or(Error::Synthesis),
                    )
                    .map(Word)
            },
        )
    }

    fn greater_than(
        &self,
        mut layouter: impl Layouter<Fp>,
        a: Self::Word,
        b: Self::Word,
    ) -> Result<(Self::Word, Self::Word), Error> {
        let config = self.config();

        layouter.assign_region(
            || "greater than",
            |mut region: Region<'_, Fp>| {
                config.s_gt.enable(&mut region, 0)?;

                a.0.copy_advice(|| "lhs", &mut region, config.advice[0], 0)?;
                b.0.copy_advice(|| "rhs", &mut region, config.advice[1], 0)?;

                let helper_cell = region
                    .assign_advice(
                        || "max minus diff",
                        config.advice[0],
                        1,
                        || {
                            let is_greater = a.0.value().unwrap().get_lower_128()
                                > b.0.value().unwrap().get_lower_128();
                            a.0.value()
                                .and_then(|a| {
                                    b.0.value().map(|b| {
                                        let x = *a - *b;

                                        (if is_greater {
                                            Fp::from(2_u64.pow(WORD_BITS))
                                        } else {
                                            Fp::zero()
                                        }) - x
                                    })
                                })
                                .ok_or(Error::Synthesis)
                        },
                    )
                    .map(Word)?;

                let is_greater_cell = region
                    .assign_advice(
                        || "is greater",
                        config.advice[1],
                        1,
                        || {
                            let is_greater = a.0.value().unwrap().get_lower_128()
                                > b.0.value().unwrap().get_lower_128();
                            Ok(if is_greater { Fp::one() } else { Fp::zero() })
                        },
                    )
                    .map(Word)?;

                Ok((helper_cell, is_greater_cell))
            },
        )
    }

    fn expose_public(
        &self,
        mut layouter: impl Layouter<Fp>,
        num: Self::Word,
        row: usize,
    ) -> Result<(), Error> {
        let config = self.config();

        layouter.constrain_instance(num.0.cell(), config.instance, row)
    }
}

#[derive(Default, Debug, Clone, Copy)]
pub struct GreaterThanCircuit<F: FieldExt, const WORD_BITS: u32> {
    pub a: Option<F>,
    pub b: Option<F>,
}

impl<const WORD_BITS: u32> Circuit<Fp> for GreaterThanCircuit<Fp, WORD_BITS> {
    type Config = (GreaterThanConfig, EvenBitsConfig);
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        let advice = [meta.advice_column(), meta.advice_column()];
        let instance = meta.instance_column();
        let constant = meta.fixed_column();

        (
            GreaterThanChip::<Fp, WORD_BITS>::configure(
                meta, advice, instance, constant,
            ),
            EvenBitsChip::<Fp, WORD_BITS>::configure(meta, advice),
        )
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        let gt_chip = GreaterThanChip::<Fp, WORD_BITS>::construct(config.0);
        let even_bits_chip = EvenBitsChip::<Fp, WORD_BITS>::construct(config.1);
        even_bits_chip.alloc_table(&mut layouter.namespace(|| "alloc table"))?;

        let a = gt_chip.load_private(layouter.namespace(|| "load a"), self.a)?;
        let b = gt_chip.load_private(layouter.namespace(|| "load b"), self.b)?;

        even_bits_chip
            .decompose(layouter.namespace(|| "a range check"), a.0.clone())?;
        even_bits_chip
            .decompose(layouter.namespace(|| "b range check"), b.0.clone())?;

        let (helper, greater_than) =
            gt_chip.greater_than(layouter.namespace(|| "a > b"), a, b)?;

        even_bits_chip
            .decompose(layouter.namespace(|| "helper range check"), helper.0)?;

        gt_chip.expose_public(layouter.namespace(|| "expose a > b"), greater_than, 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    prop_compose! {
      fn valid_triple(word_bits: u32)
              (a in 0..2u64.pow(word_bits), b in 0..2u64.pow(word_bits))
              -> (u64, u64, Vec<Fp>) {
         (a, b, vec![if a > b { Fp::one() } else { Fp::zero() }])
      }
    }

    fn gt<const WORD_BITS: u32>(
        v: Vec<(u64, u64, Vec<Fp>)>,
    ) -> Vec<(GreaterThanCircuit<Fp, WORD_BITS>, Vec<Fp>)> {
        v.into_iter()
            .map(|i| {
                (
                    GreaterThanCircuit {
                        a: Some(i.0.into()),
                        b: Some(i.1.into()),
                    },
                    i.2,
                )
            })
            .collect()
    }

    use crate::test_utils::*;

    proptest! {
        /// proptest does not support testing const generics.
        #[test]
        fn all_8_bit_words_mock_prover_test(a in 0..2u64.pow(8), b in 0..2u64.pow(8)) {
            mock_prover_test::<8>(a, b)
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig {
          cases: 20, .. ProptestConfig::default()
        })]

        #[test]
        fn all_16_bit_words_mock_prover_test(a in 0..2u64.pow(16), b in 0..2u64.pow(16)) {
            mock_prover_test::<16>(a, b)
        }

        #[test]
        fn all_8_bit_words_test(s in prop::collection::vec(valid_triple(8), 10)) {
            gen_proofs_and_verify::<8, _>(gt::<8>(s))
        }

        #[test]
        fn all_16_bit_words_test(s in prop::collection::vec(valid_triple(16), 10)) {
            gen_proofs_and_verify::<16, _>(gt::<16>(s))
        }

        #[test]
        fn all_8_bit_greater_than_tests(a in 0..2u64.pow(8), b in 0..2u64.pow(8))  {
            prop_assume!(a <= b);
            let circuit = GreaterThanCircuit::<Fp, 8> {a: Some(a.into()), b: Some(b.into())};
            gen_proofs_and_verify_should_fail::<8, _>(circuit, vec![Fp::one()])
        }

        #[test]
        fn all_8_bit_leq_tests(a in 0..2u64.pow(8), b in 0..2u64.pow(8)) {
            prop_assume!(a > b);
            let circuit = GreaterThanCircuit::<Fp, 8> {a: Some(a.into()), b: Some(b.into())};
            gen_proofs_and_verify_should_fail::<8, _>(circuit, vec![Fp::zero()])
        }

        #[test]
        fn all_16_bit_greater_than_tests(a in 0..2u64.pow(16), b in 0..2u64.pow(16))  {
            prop_assume!(a <= b);
            let circuit = GreaterThanCircuit::<Fp, 16> {a: Some(a.into()), b: Some(b.into())};
            gen_proofs_and_verify_should_fail::<16, _>(circuit, vec![Fp::one()])
        }

        #[test]
        fn all_16_bit_leq_tests(a in 0..2u64.pow(16), b in 0..2u64.pow(16)) {
            prop_assume!(a > b);
            let circuit = GreaterThanCircuit::<Fp, 16> {a: Some(a.into()), b: Some(b.into())};
            gen_proofs_and_verify_should_fail::<16, _>(circuit, vec![Fp::zero()])
        }
    }

    proptest! {
        // The case number was picked to run all tests in about 60 seconds on my machine.
        // TODO use `plonk::BatchVerifier` to speed up tests.
        #![proptest_config(ProptestConfig {
          cases: 10, .. ProptestConfig::default()
        })]

        #[test]
        fn all_24_bit_words_mock_prover_test(a in 0..2u64.pow(24), b in 0..2u64.pow(24)) {
            mock_prover_test::<24>(a, b)
        }

        #[test]
        fn all_24_bit_words_test(s in prop::collection::vec(valid_triple(24), 10)) {
            gen_proofs_and_verify::<24, _>(gt::<24>(s))
        }

        #[test]
        fn all_24_bit_greater_than_tests(a in 0..2u64.pow(24), b in 0..2u64.pow(24))  {
            prop_assume!(a <= b);
            let circuit = GreaterThanCircuit::<Fp, 24> {a: Some(a.into()), b: Some(b.into())};
            gen_proofs_and_verify_should_fail::<24, _>(circuit, vec![Fp::one()])
        }

        #[test]
        fn all_24_bit_leq_tests(a in 0..2u64.pow(24), b in 0..2u64.pow(24)) {
            prop_assume!(a > b);
            let circuit = GreaterThanCircuit::<Fp, 24> {a: Some(a.into()), b: Some(b.into())};
            gen_proofs_and_verify_should_fail::<24, _>(circuit, vec![Fp::zero()])
        }
    }

    // It's used in the proptests
    #[allow(unused)]
    fn mock_prover_test<const WORD_BITS: u32>(a: u64, b: u64) {
        let k = 1 + WORD_BITS / 2;
        let circuit: GreaterThanCircuit<Fp, WORD_BITS> = GreaterThanCircuit {
            a: Some(Fp::from(a)),
            b: Some(Fp::from(b)),
        };

        let c = if a > b { Fp::one() } else { Fp::zero() };

        // Arrange the public input. We expose the bitwise AND result in row 0
        // of the instance column, so we position it there in our public inputs.
        let public_inputs = vec![c];

        // Given the correct public input, our circuit will verify.
        let prover = MockProver::run(k, &circuit, vec![public_inputs]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn zeros_mock_prover_test() {
        const WORD_BITS: u32 = 24;
        let a = 0;
        let b = 0;
        let k = 1 + WORD_BITS / 2;
        let circuit = GreaterThanCircuit::<Fp, WORD_BITS> {
            a: Some(Fp::from(a)),
            b: Some(Fp::from(b)),
        };

        let c = if a > b { Fp::one() } else { Fp::zero() };

        // Arrange the public input. We expose the bitwise AND result in row 0
        // of the instance column, so we position it there in our public inputs.
        let public_inputs = vec![c];

        // Given the correct public input, our circuit will verify.
        let prover = MockProver::run(k, &circuit, vec![public_inputs]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn circuit_layout_test() {
        const WORD_BITS: u32 = 8;
        let k = 5;

        // Prepare the private and public inputs to the circuit!
        const A: u64 = 7;
        const B: u64 = 6;
        let a = Fp::from(A);
        let b = Fp::from(B);

        // Instantiate the circuit with the private inputs.
        let circuit = GreaterThanCircuit::<Fp, WORD_BITS> {
            a: Some(a),
            b: Some(b),
        };
        use plotters::prelude::*;
        let root =
            BitMapBackend::new("layout.png", (1920, 1080)).into_drawing_area();
        root.fill(&WHITE).unwrap();
        let root = root
            .titled("Bitwise AND Circuit Layout", ("sans-serif", 60))
            .unwrap();

        halo2_proofs::dev::CircuitLayout::default()
            .mark_equality_cells(true)
            .show_equality_constraints(true)
            // The first argument is the size parameter for the circuit.
            .render(k, &circuit, &root)
            .unwrap();

        let dot_string = halo2_proofs::dev::circuit_dot_graph(&circuit);
        let mut dot_graph = std::fs::File::create("circuit.dot").unwrap();
        std::io::Write::write_all(&mut dot_graph, dot_string.as_bytes()).unwrap();
    }
}
