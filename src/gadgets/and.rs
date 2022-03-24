use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{AssignedCell, Chip, Layouter, Region, SimpleFloorPlanner},
    dev::MockProver,
    plonk::{
        Advice, BatchVerifier, Circuit, Column, ConstraintSystem, Error, Expression, Fixed,
        Instance, Selector,
    },
    poly::Rotation,
};
use pasta_curves::Fp;
use std::marker::PhantomData;

pub trait NumericInstructions<F: FieldExt>: Chip<F> {
    /// Variable representing a number.
    type Word;

    /// Loads a number into the circuit as a private input.
    /// TODO replace this like expose_public
    fn load_private(&self, layouter: impl Layouter<F>, a: Option<F>) -> Result<Self::Word, Error>;

    fn add(
        &self,
        layouter: impl Layouter<F>,
        a: Self::Word,
        b: Self::Word,
    ) -> Result<Self::Word, Error>;

    fn compose(
        &self,
        layouter: impl Layouter<F>,
        a: Self::Word,
        b: Self::Word,
    ) -> Result<Self::Word, Error>;
}

/// The chip that will implement our instructions! Chips store their own
/// config, as well as type markers if necessary.
pub struct AndChip<F: FieldExt, const WORD_BITS: u32> {
    config: AndConfig,
    _marker: PhantomData<F>,
}

/// Chip state is stored in a config struct. This is generated by the chip
/// during configuration, and then stored inside the chip.
#[derive(Clone, Copy, Debug)]
pub struct AndConfig {
    /// For this chip, we will use two advice columns to implement our instructions.
    /// These are also the columns through which we communicate with other parts of
    /// the circuit.
    advice: [Column<Advice>; 2],

    // We need a selector to enable the add gate, so that we aren't placing
    // any constraints on cells where `NumericInstructions::add` is not being used.
    // This is important when building larger circuits, where columns are used by
    // multiple sets of instructions.
    s_add: Selector,
    s_compose: Selector,
}

impl<F: FieldExt, const WORD_BITS: u32> AndChip<F, WORD_BITS> {
    pub fn construct(config: <Self as Chip<F>>::Config) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        advice: [Column<Advice>; 2],
        constant: Column<Fixed>,
    ) -> <Self as Chip<F>>::Config {
        meta.enable_constant(constant);
        for column in &advice {
            meta.enable_equality(*column);
        }
        let s_add = meta.selector();
        let s_compose = meta.selector();

        meta.create_gate("add", |meta| {
            let lhs = meta.query_advice(advice[0], Rotation::cur());
            let rhs = meta.query_advice(advice[1], Rotation::cur());
            let out = meta.query_advice(advice[0], Rotation::next());
            let s_add = meta.query_selector(s_add);

            // Finally, we return the polynomial expressions that constrain this gate.
            // For our multiplication gate, we only need a single polynomial constraint.
            //
            // The polynomial expressions returned from `create_gate` will be
            // constrained by the proving system to equal zero. Our expression
            vec![s_add * (lhs + rhs - out)]
        });

        meta.create_gate("compose", |meta| {
            let lhs = meta.query_advice(advice[0], Rotation::cur());
            let rhs = meta.query_advice(advice[1], Rotation::cur());
            let out = meta.query_advice(advice[0], Rotation::next());
            let s_compose = meta.query_selector(s_compose);

            // Finally, we return the polynomial expressions that constrain this gate.
            // For our multiplication gate, we only need a single polynomial constraint.
            //
            // The polynomial expressions returned from `create_gate` will be
            // constrained by the proving system to equal zero. Our expression
            vec![s_compose * (lhs + Expression::Constant(F::from(2)) * rhs - out)]
        });

        AndConfig {
            advice,
            s_add,
            s_compose,
        }
    }
}

impl<F: FieldExt, const WORD_BITS: u32> Chip<F> for AndChip<F, WORD_BITS> {
    type Config = AndConfig;
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

impl<const WORD_BITS: u32> NumericInstructions<Fp> for AndChip<Fp, WORD_BITS> {
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

    fn add(
        &self,
        mut layouter: impl Layouter<Fp>,
        a: Self::Word,
        b: Self::Word,
    ) -> Result<Self::Word, Error> {
        let config = self.config();

        layouter.assign_region(
            || "add",
            |mut region: Region<'_, Fp>| {
                // We only want to use a single addition gate in this region,
                // so we enable it at region offset 0; this means it will constrain
                // cells at offsets 0 and 1.
                config.s_add.enable(&mut region, 0)?;

                // The inputs we've been given could be located anywhere in the circuit,
                // but we can only rely on relative offsets inside this region. So we
                // assign new cells inside the region and constrain them to have the
                // same values as the inputs.
                a.0.copy_advice(|| "lhs", &mut region, config.advice[0], 0)?;
                b.0.copy_advice(|| "rhs", &mut region, config.advice[1], 0)?;

                // Now we can assign the addition result, which is to be assigned
                // into the output position.
                let value = a.0.value().and_then(|a| b.0.value().map(|b| *a + *b));

                // Finally, we do the assignment to the output, returning a
                // variable to be used in another part of the circuit.
                region
                    .assign_advice(
                        || "lhs + rhs",
                        config.advice[0],
                        1,
                        || value.ok_or(Error::Synthesis),
                    )
                    .map(Word)
            },
        )
    }

    fn compose(
        &self,
        mut layouter: impl Layouter<Fp>,
        a: Self::Word,
        b: Self::Word,
    ) -> Result<Self::Word, Error> {
        let config = self.config();

        layouter.assign_region(
            || "compose",
            |mut region: Region<'_, Fp>| {
                config.s_compose.enable(&mut region, 0)?;
                a.0.copy_advice(|| "lhs", &mut region, config.advice[0], 0)?;
                b.0.copy_advice(|| "rhs", &mut region, config.advice[1], 0)?;
                let value =
                    a.0.value()
                        .and_then(|a| b.0.value().map(|b| *a + Fp::from(2) * *b));

                region
                    .assign_advice(
                        || "lhs + rhs",
                        config.advice[0],
                        1,
                        || value.ok_or(Error::Synthesis),
                    )
                    .map(Word)
            },
        )
    }
}

fn expose_public<F: FieldExt>(
    instance: Column<Instance>,
    mut layouter: impl Layouter<F>,
    num: Word<F>,
    row: usize,
) -> Result<(), Error> {
    layouter.constrain_instance(num.0.cell(), instance, row)
}

/// The full circuit implementation.
///
/// In this struct we store the private input variables. We use `Option<F>` because
/// they won't have any value during key generation. During proving, if any of these
/// were `None` we would get an error.
#[derive(Default)]
pub struct AndCircuit<F: FieldExt, const WORD_BITS: u32 = 8> {
    pub a: Option<F>,
    pub b: Option<F>,
}

impl<const WORD_BITS: u32> Circuit<Fp> for AndCircuit<Fp, WORD_BITS> {
    type Config = (AndConfig, EvenBitsConfig, Column<Instance>);
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        // We create the two advice columns that AndChip uses for I/O.
        let advice = [meta.advice_column(), meta.advice_column()];

        // Create a fixed column to load constants.
        let constant = meta.fixed_column();

        // We also need an instance column to store public inputs.
        let instance = meta.instance_column();
        meta.enable_equality(instance);

        (
            AndChip::<Fp, WORD_BITS>::configure(meta, advice, constant),
            EvenBitsChip::<Fp, WORD_BITS>::configure(meta, advice),
            instance,
        )
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        let and_chip = AndChip::<Fp, WORD_BITS>::construct(config.0);
        let even_bits_chip = EvenBitsChip::<Fp, WORD_BITS>::construct(config.1);
        even_bits_chip.alloc_table(&mut layouter.namespace(|| "alloc table"))?;
        let public_input = config.2;

        // Load our private values into the circuit.
        // index 0
        let a = and_chip.load_private(layouter.namespace(|| "load a"), self.a)?;
        // index 1
        let b = and_chip.load_private(layouter.namespace(|| "load b"), self.b)?;

        // index 2
        let (ae, ao) = even_bits_chip.decompose(layouter.namespace(|| "a decomposition"), a.0)?;

        // index 3
        let (be, bo) = even_bits_chip.decompose(layouter.namespace(|| "b decomposition"), b.0)?;

        // index 4
        let e = and_chip.add(layouter.namespace(|| "ae + be"), Word(ae.0), Word(be.0))?;
        // index 5
        let o = and_chip.add(layouter.namespace(|| "ao + be"), Word(ao.0), Word(bo.0))?;

        // // index 6
        let (_ee, eo) = even_bits_chip.decompose(layouter.namespace(|| "e decomposition"), e.0)?;

        // index 7
        let (_oe, oo) = even_bits_chip.decompose(layouter.namespace(|| "o decomposition"), o.0)?;

        // // index 8
        let a_and_b = and_chip.compose(
            layouter.namespace(|| "compose eo and oo"),
            Word(eo.0),
            Word(oo.0),
        )?;

        // Expose the result as a public input to the circuit.
        expose_public(
            public_input,
            layouter.namespace(|| "expose a_and_b"),
            a_and_b,
            0,
        )
    }
}

use proptest::prelude::*;

use super::tables::even_bits::{EvenBitsChip, EvenBitsConfig, EvenBitsLookup};

prop_compose! {
  fn valid_triple(word_bits: u32)
          (a in 0..2u64.pow(word_bits), b in 0..2u64.pow(word_bits))
          -> (u64, u64, u64) {
    let c = a & b;
    (a, b, c)
  }
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
        gen_proofs_and_verify::<8>(&s, true)
    }

    #[test]
    fn all_16_bit_words_mock_prover_test(a in 0..2u64.pow(16), b in 0..2u64.pow(16)) {
        mock_prover_test::<16>(a, b)
    }

    #[test]
    fn all_16_bit_words_test(s in prop::collection::vec(valid_triple(16), 10)) {
        gen_proofs_and_verify::<16>(&s, true)
    }

    #[test]
    #[should_panic]
    fn all_8_bit_words_test_bad_proof(a in 0..2u64.pow(8), b in 0..2u64.pow(8), c in 0..2u64.pow(8)) {
        prop_assume!(c != a & b);
        gen_proofs_and_verify::<8>(&[(a, b, c)], false)
    }

    // TODO mix valid and invalid
    #[test]
    #[should_panic]
    fn all_16_bit_words_test_bad_proof(a in 0..2u64.pow(16), b in 0..2u64.pow(16), c in 0..2u64.pow(16)) {
        prop_assume!(c != a & b);
        gen_proofs_and_verify::<16>(&[(a, b, c)], false)
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
        gen_proofs_and_verify::<24>(&s, false)
    }

    #[test]
    #[should_panic]
    fn all_24_bit_words_test_bad_proof(a in 0..2u64.pow(24), b in 0..2u64.pow(24), c in 0..2u64.pow(24)) {
        prop_assume!(c != a & b);
        gen_proofs_and_verify::<24>(&[(a, b, c)], false)
    }
}

// It's used in the proptests
#[allow(unused)]
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

// TODO move into test module
// It's used in the proptests
#[allow(unused)]
fn gen_proofs_and_verify<const WORD_BITS: u32>(inputs: &[(u64, u64, u64)], retry: bool) {
    use halo2_proofs::{
        plonk::{create_proof, keygen_pk, keygen_vk, verify_proof, SingleVerifier},
        poly::commitment::Params,
        transcript::{Blake2bRead, Blake2bWrite},
    };
    use pasta_curves::{vesta, EqAffine};
    use rand_core::OsRng;

    let k = 1 + WORD_BITS / 2;
    let params: Params<EqAffine> = halo2_proofs::poly::commitment::Params::new(k);
    let empty_circuit = AndCircuit::<Fp, WORD_BITS>::default();
    let vk = keygen_vk(&params, &empty_circuit).unwrap();

    let pk = keygen_pk(&params, vk, &empty_circuit).unwrap();

    let proofs: Vec<(Vec<u8>, Fp)> = inputs
        .iter()
        .map(|(a, b, c)| {
            let circuit = AndCircuit::<Fp, WORD_BITS> {
                a: Some(Fp::from(*a)),
                b: Some(Fp::from(*b)),
            };
            let c = Fp::from(*c);

            let mut transcript = Blake2bWrite::<_, vesta::Affine, _>::init(vec![]);
            create_proof(
                &params,
                &pk,
                &[circuit],
                &[&[&[c]]],
                &mut OsRng,
                &mut transcript,
            )
            .expect("Failed to create proof");

            let proof: Vec<u8> = transcript.finalize();
            (proof, c)
        })
        .collect();

    let mut verifier = BatchVerifier::new(&params, OsRng);
    for (proof, c) in &proofs {
        let mut transcript = Blake2bRead::init(&proof[..]);

        verifier = verify_proof(&params, pk.get_vk(), verifier, &[&[&[*c]]], &mut transcript)
            .expect("could not verify_proof");
    }

    let verified = verifier.finalize();
    if !retry {
        assert!(verified, "One of the proofs could not be verified");
    } else if !verified {
        for (proof, c) in proofs {
            let mut verifier = SingleVerifier::new(&params);
            let mut transcript = Blake2bRead::init(&proof[..]);

            verify_proof(&params, pk.get_vk(), verifier, &[&[&[c]]], &mut transcript)
                .expect("could not verify_proof");
        }
    }
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
    let root = BitMapBackend::new("layout.png", (1920, 1080)).into_drawing_area();
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
