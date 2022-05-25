use crate::assign::ConstraintSys;
use crate::circuits::tables::even_bits::EvenBitsConfig;
use halo2_proofs::circuit::Region;
use halo2_proofs::pasta::Fp;
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{AssignedCell, Chip, Layouter, SimpleFloorPlanner},
    plonk::{
        Advice, Circuit, Column, ConstraintSystem, Error, Expression, Instance,
        Selector,
    },
    poly::Rotation,
};
use std::marker::PhantomData;

use super::tables::even_bits::EvenBitsTable;

#[derive(Debug, Clone, Copy)]
pub struct AndConfig<const WORD_BITS: u32> {
    /// A Selector denoting the extent of the exe table.
    s_table: Selector,
    /// An advice columns that acts as a selector for Annd's gates.
    /// `Out.and`
    s_and: Column<Advice>,

    a: EvenBitsConfig<WORD_BITS>,
    b: EvenBitsConfig<WORD_BITS>,

    /// lhs_e + rhs_e
    even_sum: EvenBitsConfig<WORD_BITS>,
    /// lhs_o + rhs_o
    odd_sum: EvenBitsConfig<WORD_BITS>,

    /// Stores `lhs.word & rhs.word`
    /// Constrained by: composing eo and oo
    res: Column<Advice>,
}

impl<const WORD_BITS: u32> AndConfig<WORD_BITS> {
    pub fn configure<F: FieldExt>(
        meta: &mut impl ConstraintSys<F, Column<Advice>>,
        even_bits: EvenBitsTable<WORD_BITS>,
        s_table: Selector,
        s_and: Column<Advice>,

        a: Column<Advice>,
        b: Column<Advice>,
        res: Column<Advice>,
    ) -> Self {
        let a = EvenBitsConfig::configure(meta, a, s_and, s_table, even_bits);
        let b = EvenBitsConfig::configure(meta, b, s_and, s_table, even_bits);

        let add_gate = |meta: &mut ConstraintSystem<F>, lhs, rhs, res| {
            meta.create_gate("add", |meta| {
                let lhs = meta.query_advice(lhs, Rotation::cur());
                let rhs = meta.query_advice(rhs, Rotation::cur());
                let res = meta.query_advice(res, Rotation::cur());
                let s_table = meta.query_selector(s_table);
                let s_and = meta.query_advice(s_and, Rotation::cur());

                vec![s_table * s_and * (lhs + rhs - res)]
            })
        };

        let even_sum = meta.new_column();
        let even_sum = EvenBitsConfig::<WORD_BITS>::configure(
            meta,
            even_sum,
            s_and,
            s_table,
            a.even_bits,
        );

        let odd_sum = meta.new_column();
        let odd_sum = EvenBitsConfig::<WORD_BITS>::configure(
            meta,
            odd_sum,
            s_and,
            s_table,
            a.even_bits,
        );

        let meta = meta.cs();
        add_gate(meta, a.even, b.even, even_sum.word);
        add_gate(meta, a.odd, b.odd, odd_sum.word);

        // We don't need to add gates for decomposing and looking up `even_sum`, and `odd_sum`,
        // since those gates have already been added in `EvenBitsConfig::configure`.

        meta.create_gate("compose", |meta| {
            let eo = meta.query_advice(even_sum.odd, Rotation::cur());
            let oo = meta.query_advice(odd_sum.odd, Rotation::cur());
            let res = meta.query_advice(res, Rotation::cur());
            let s_table = meta.query_selector(s_table);
            let s_and = meta.query_advice(s_and, Rotation::cur());

            vec![
                s_table * s_and * (eo + Expression::Constant(F::from(2)) * oo - res),
            ]
        });

        Self {
            s_table,
            s_and,
            a,
            b,
            even_sum,
            odd_sum,
            res,
        }
    }

    pub fn assign_and<F: FieldExt>(
        &self,
        region: &mut Region<'_, F>,
        lhs: F,
        rhs: F,
        offset: usize,
    ) -> AssignedCell<F, F> {
        let (rhs_e, rhs_o) = self.b.assign_decompose(region, offset, rhs);
        let (lhs_e, lhs_o) = self.a.assign_decompose(region, offset, lhs);

        let even_sum = *lhs_e + *rhs_e;
        region
            .assign_advice(
                || "lhs_e + rhs_e",
                self.even_sum.word,
                offset,
                || Ok(even_sum),
            )
            .unwrap();
        self.even_sum.assign_decompose(region, offset, even_sum);

        let odd_sum = *lhs_o + *rhs_o;
        region
            .assign_advice(
                || "lhs_o + rhs_o",
                self.odd_sum.word,
                offset,
                || Ok(odd_sum),
            )
            .unwrap();
        self.odd_sum.assign_decompose(region, offset, odd_sum);

        let res = F::from_u128(lhs.get_lower_128() & rhs.get_lower_128());
        let res = region
            .assign_advice(|| "res", self.res, offset, || Ok(res))
            .unwrap();
        res
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
    config: AndConfig<WORD_BITS>,
    _marker: PhantomData<F>,
}

impl<F: FieldExt, const WORD_BITS: u32> Chip<F> for AndChip<F, WORD_BITS> {
    type Config = AndConfig<WORD_BITS>;
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
pub struct Word<F: FieldExt>(pub AssignedCell<F, F>);

/// The full circuit implementation.
///
/// In this struct we store the private input variables. We use `Option<F>` because
/// they won't have any value during key generation. During proving, if any of these
/// were `None` we would get an error.
#[derive(Default, Debug, Clone, Copy)]
pub struct AndCircuit<F: FieldExt, const WORD_BITS: u32> {
    pub a: Option<F>,
    pub b: Option<F>,
}

impl<const WORD_BITS: u32> Circuit<Fp> for AndCircuit<Fp, WORD_BITS> {
    type Config = (AndConfig<WORD_BITS>, Column<Instance>);
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        let instance = meta.instance_column();
        meta.enable_equality(instance);

        let s_table = meta.complex_selector();
        let s_and = meta.advice_column();
        let res = meta.advice_column();
        meta.enable_equality(res);

        let even_bits = EvenBitsTable::new(meta);

        let a = meta.advice_column();
        meta.enable_equality(a);

        let b = meta.advice_column();
        meta.enable_equality(b);

        (
            AndConfig::<WORD_BITS>::configure(
                meta, even_bits, s_table, s_and, a, b, res,
            ),
            instance,
        )
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        // This is not a great method of initializing even_bits, maybe bring back `WithEvenBits`.
        config
            .0
            .a
            .even_bits
            .alloc_table(&mut layouter.namespace(|| "alloc table"))?;

        layouter
            .assign_region(
                || "and",
                |mut region| {
                    config.0.s_table.enable(&mut region, 0).unwrap();
                    region
                        .assign_advice(
                            || "s_add",
                            config.0.s_and,
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
                            .assign_advice(|| "lhs", config.0.a.word, 0, || Ok(lhs))
                            .unwrap();
                        region
                            .assign_advice(|| "rhs", config.0.b.word, 0, || Ok(rhs))
                            .unwrap();

                        config.0.assign_and(&mut region, lhs, rhs, 0);
                        // load public
                    }

                    region
                        .assign_advice_from_instance(
                            || "res",
                            config.1,
                            0,
                            config.0.res,
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
    use crate::test_utils::*;
    use halo2_proofs::dev::MockProver;
    use proptest::prelude::*;

    prop_compose! {
      fn valid_triple(word_bits: u32)
              (a in 0..2u64.pow(word_bits), b in 0..2u64.pow(word_bits))
              -> (u64, u64, u64) {
        let c = a & b;
        (a, b, c)
      }
    }

    fn and<const WORD_BITS: u32>(
        v: Vec<(u64, u64, u64)>,
    ) -> Vec<(AndCircuit<Fp, WORD_BITS>, Vec<Vec<Fp>>)> {
        v.into_iter()
            .map(|i| {
                (
                    AndCircuit {
                        a: Some(i.0.into()),
                        b: Some(i.1.into()),
                    },
                    vec![vec![i.2.into()]],
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
        fn all_8_bit_words_mock_prover_test(a in 0..2u64.pow(8), b in 0..2u64.pow(8)) {
            mock_prover_test::<8>(a, b)
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig {
          cases: 20, .. ProptestConfig::default()
        })]

        #[test]
        fn all_8_bit_words_test(s in prop::collection::vec(valid_triple(8), 10)) {
            gen_proofs_and_verify::<8, _>(and::<8>(s))
        }

        #[test]
        fn all_16_bit_words_mock_prover_test(a in 0..2u64.pow(16), b in 0..2u64.pow(16)) {
            mock_prover_test::<16>(a, b)
        }

        #[test]
        fn all_16_bit_words_test(s in prop::collection::vec(valid_triple(16), 10)) {
            gen_proofs_and_verify::<16, _>(and::<16>(s))
        }

        #[test]
        fn all_8_bit_words_test_bad_proof(a in 0..2u64.pow(8), b in 0..2u64.pow(8), c in 0..2u64.pow(8)) {
            prop_assume!(c != a & b);
            let circuit = AndCircuit::<Fp, 8> {a: Some(a.into()), b: Some(b.into())};
            gen_proofs_and_verify_should_fail::<8, _>(circuit, vec![c.into()])
        }

        // TODO mix valid and invalid
        #[test]
        fn all_16_bit_words_test_bad_proof(a in 0..2u64.pow(16), b in 0..2u64.pow(16), c in 0..2u64.pow(16)) {
            prop_assume!(c != a & b);
            let circuit = AndCircuit::<Fp, 16> {a: Some(a.into()), b: Some(b.into())};
            gen_proofs_and_verify_should_fail::<16, _>(circuit, vec![c.into()])
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
            gen_proofs_and_verify::<24, _>(and::<24>(s))
        }

        #[test]
        fn all_24_bit_words_test_bad_proof(a in 0..2u64.pow(24), b in 0..2u64.pow(24), c in 0..2u64.pow(24)) {
            prop_assume!(c != a & b);
            let circuit = AndCircuit::<Fp, 24> {a: Some(a.into()), b: Some(b.into())};
            gen_proofs_and_verify_should_fail::<24, _>(circuit, vec![c.into()])
        }
    }

    // It's used in the proptests
    fn mock_prover_test<const WORD_BITS: u32>(a: u64, b: u64) {
        let k = 1 + WORD_BITS / 2;
        let circuit: AndCircuit<Fp, WORD_BITS> = AndCircuit {
            a: Some(Fp::from(a)),
            b: Some(Fp::from(b)),
        };

        let c = Fp::from(a & b);

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
        let circuit = AndCircuit::<Fp, WORD_BITS> {
            a: Some(Fp::from(a)),
            b: Some(Fp::from(b)),
        };

        let c = Fp::from(a & b);

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
        let circuit = AndCircuit::<Fp, WORD_BITS> {
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
