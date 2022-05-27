use crate::assign::ConstraintSys;

use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{AssignedCell, Chip, Layouter, Region, SimpleFloorPlanner},
    pasta::Fp,
    plonk::{
        Advice, Circuit, Column, ConstraintSystem, Error, Expression, Instance,
        Selector,
    },
    poly::Rotation,
};
use std::marker::PhantomData;

pub struct GreaterThanChip<F: FieldExt, const WORD_BITS: u32> {
    config: GreaterThanConfig,
    _marker: PhantomData<F>,
}

#[derive(Clone, Debug)]
pub struct GreaterThanConfig {
    /// A Selector denoting the extent of the exe table.
    s_table: Selector,

    /// An advice columns that acts as a selector for Annd's gates.
    /// `Out.greater_than`
    s_gt: Column<Advice>,
    a: Column<Advice>,
    b: Column<Advice>,
    // 1 if a is greater than b.
    // 0 if not.
    res: Column<Advice>,

    helper: Column<Advice>,
}

impl GreaterThanConfig {
    fn configure<
        F: FieldExt,
        const WORD_BITS: u32,
        M: ConstraintSys<F, Column<Advice>>,
    >(
        meta: &mut M,
        s_table: Selector,
        s_gt: Column<Advice>,

        a: Column<Advice>,
        b: Column<Advice>,
        res: Column<Advice>,
    ) -> Self {
        let helper = meta.new_column();

        let meta = meta.cs();
        meta.create_gate("greater than", |meta| {
            let s_table = meta.query_selector(s_table);
            let s_gt = meta.query_advice(s_gt, Rotation::cur());

            let a = meta.query_advice(a, Rotation::cur());
            let b = meta.query_advice(b, Rotation::cur());

            // this value is `lhs - rhs` if `lhs !> rhs` and `2^W - (lhs - rhs)` if `lhs > rhs`
            let helper = meta.query_advice(helper, Rotation::cur());

            let res = meta.query_advice(res, Rotation::cur());

            vec![
                s_table
                    * s_gt
                    * (a - b + helper
                        - Expression::Constant(F::from(2_u64.pow(WORD_BITS))) * res),
            ]
        });

        GreaterThanConfig {
            s_table,
            s_gt,
            a,
            b,
            res,
            helper,
        }
    }

    fn assign_greater_than<F: FieldExt, const WORD_BITS: u32>(
        &self,
        region: &mut Region<'_, F>,
        a: F,
        b: F,
        offset: usize,
    ) {
        let is_greater = a.get_lower_128() > b.get_lower_128();
        let _ = region
            .assign_advice(
                || "max minus diff",
                self.helper,
                offset,
                || {
                    let x = a - b;

                    Ok((if is_greater {
                        F::from(2_u64.pow(WORD_BITS))
                    } else {
                        F::zero()
                    }) - x)
                },
            )
            .unwrap();

        let _ = region
            .assign_advice(
                || "is greater res",
                self.res,
                offset,
                || Ok(if is_greater { F::one() } else { F::zero() }),
            )
            .unwrap();
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

#[derive(Default, Debug, Clone, Copy)]
pub struct GreaterThanCircuit<F: FieldExt, const WORD_BITS: u32> {
    pub a: Option<F>,
    pub b: Option<F>,
}

impl<const WORD_BITS: u32> Circuit<Fp> for GreaterThanCircuit<Fp, WORD_BITS> {
    type Config = (GreaterThanConfig, Column<Instance>);
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        let s_table = meta.selector();
        let s_gt = meta.advice_column();
        let a = meta.advice_column();
        let b = meta.advice_column();
        let is_greater = meta.advice_column();

        let input = meta.instance_column();
        meta.enable_equality(input);
        meta.enable_equality(is_greater);

        (
            GreaterThanConfig::configure::<Fp, WORD_BITS, _>(
                meta, s_table, s_gt, a, b, is_greater,
            ),
            input,
        )
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        let gt_config = config.0;

        layouter
            .assign_region(
                || "greater_than",
                |mut region| {
                    gt_config.s_table.enable(&mut region, 0).unwrap();
                    region
                        .assign_advice(
                            || "s_gt",
                            gt_config.s_gt,
                            0,
                            || Ok(Fp::one()),
                        )
                        .unwrap();

                    // If a or b is None then we will see the error early.
                    if self.a.is_some() || self.b.is_some() {
                        // load private
                        let lhs = self.a.unwrap();
                        let rhs = self.b.unwrap();

                        region
                            .assign_advice(|| "a", gt_config.a, 0, || Ok(lhs))
                            .unwrap();
                        region
                            .assign_advice(|| "b", gt_config.b, 0, || Ok(rhs))
                            .unwrap();

                        gt_config.assign_greater_than::<Fp, WORD_BITS>(
                            &mut region,
                            lhs,
                            rhs,
                            0,
                        );
                    }

                    // load public
                    region
                        .assign_advice_from_instance(
                            || "res",
                            config.1,
                            0,
                            gt_config.res,
                            0,
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
    use halo2_proofs::dev::MockProver;
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
    ) -> Vec<(GreaterThanCircuit<Fp, WORD_BITS>, Vec<Vec<Fp>>)> {
        v.into_iter()
            .map(|i| {
                (
                    GreaterThanCircuit {
                        a: Some(i.0.into()),
                        b: Some(i.1.into()),
                    },
                    vec![i.2],
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
