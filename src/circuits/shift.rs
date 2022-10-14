use crate::assign::ConstraintSys;
use crate::trace::{get_word_size_bit_mask_msb, truncate};
use halo2_proofs::circuit::{Region, Value};
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

use super::tables::even_bits::{self, EvenBitsConfig, EvenBitsTable};
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

    a_shift: Column<Advice>,
    a_power: Column<Advice>,
    r_decompose: EvenBitsConfig<WORD_BITS>,

    pow: PowTable<WORD_BITS>,
}

impl<const WORD_BITS: u32> ShiftConfig<WORD_BITS> {
    #[allow(clippy::complexity)]
    pub fn new(
        s_table: Selector,
        s_shift: Column<Advice>,

        a: Column<Advice>,
        b: Column<Advice>,
        c: Column<Advice>,
        d: Column<Advice>,

        a_shift: Column<Advice>,
        a_power: Column<Advice>,
        r_decompose: EvenBitsConfig<WORD_BITS>,

        pow: PowTable<WORD_BITS>,
    ) -> Self {
        Self {
            s_table,
            s_shift,
            a,
            b,
            c,
            d,
            a_shift,
            a_power,
            r_decompose,
            pow,
        }
    }

    #[allow(clippy::complexity)]
    pub fn configure<F: FieldExt>(
        meta: &mut impl ConstraintSys<F, Column<Advice>>,
        s_table: Selector,
        s_shift: Column<Advice>,

        a: Column<Advice>,
        b: Column<Advice>,
        c: Column<Advice>,
        d: Column<Advice>,

        a_shift: Column<Advice>,
        a_power: Column<Advice>,
        r_decompose: EvenBitsConfig<WORD_BITS>,

        pow: PowTable<WORD_BITS>,
    ) -> Self {
        let conf @ Self {
            s_table,
            s_shift,
            a,
            b,
            c,
            d,
            a_shift,
            a_power,
            r_decompose,
            pow,
        } = Self::new(
            s_table,
            s_shift,
            a,
            b,
            c,
            d,
            a_shift,
            a_power,
            r_decompose,
            pow,
        );

        meta.cs().create_gate("shift", |meta| {
            let one = Expression::Constant(F::one());
            let two = Expression::Constant(F::from(2));
            let word_bits = Expression::Constant(F::from(WORD_BITS as u64));
            // The cardinality of Word 2^W
            let card = Expression::Constant(F::from(2u64.pow(WORD_BITS)));

            let s_table = meta.query_selector(s_table);
            let s_shift = meta.query_advice(s_shift, Rotation::cur());

            let a = meta.query_advice(a, Rotation::cur());
            let b = meta.query_advice(b, Rotation::cur());
            let c = meta.query_advice(c, Rotation::cur());
            let d = meta.query_advice(d, Rotation::cur());

            let r_o = meta.query_advice(r_decompose.odd, Rotation::cur());
            let r_e = meta.query_advice(r_decompose.even, Rotation::cur());

            let a_shift = meta.query_advice(a_shift, Rotation::cur());
            let a_power = meta.query_advice(a_power, Rotation::cur());

            Constraints::with_selector(
                s_table * s_shift,
                [
                    // a_shift is 1 or zero
                    a_shift.clone() * (a_shift.clone() - one.clone()),
                    // Redundant with FLAG4 (page 31)
                    (one - a_shift) * (word_bits - a - (two * r_o) - r_e),
                    // SHIFT
                    dbg!(a_power) * dbg!(b) - dbg!(d) - dbg!(card) * dbg!(c),
                ],
            )
        });

        let _ = meta.cs().lookup(|meta| {
            let one = Expression::Constant(F::one());
            let word_bits = Expression::Constant(F::from(WORD_BITS as u64));

            // let s_table = meta.query_selector(s_table);
            let s_shift = meta.query_advice(s_shift, Rotation::cur());
            let a = meta.query_advice(a, Rotation::cur());

            let a_shift = meta.query_advice(a_shift, Rotation::cur());
            let a_power = meta.query_advice(a_power, Rotation::cur());

            vec![
                (
                    s_shift.clone() * (a.clone() + a_shift * (word_bits - a)),
                    pow.values,
                ),
                // When s_shift not set, we lookup (value: 0, value: 1)
                // In the paper this is just (a_power, pow.powers)
                (
                    (s_shift.clone() * a_power) + one.clone() - (s_shift * one),
                    pow.powers,
                ),
            ]
        });

        conf
    }

    pub fn assign_shift<F: FieldExt>(
        &self,
        region: &mut Region<'_, F>,
        shift_bits: u128,
        c: u128,
        offset: usize,
    ) {
        let a_shift = WORD_BITS < shift_bits as _;
        region
            .assign_advice(
                || "a_shift",
                self.a_shift,
                offset,
                || Value::known(F::from(a_shift)),
            )
            .unwrap();

        let a_power = if a_shift {
            0
        } else {
            2u64.pow(shift_bits.try_into().unwrap()) % 2u64.pow(WORD_BITS)
        };
        region
            .assign_advice(
                || "a_power",
                self.a_power,
                offset,
                || Value::known(F::from(a_power)),
            )
            .unwrap();

        let r = F::from(if c == 0 {
            0
        } else {
            c as u64 - shift_bits as u64 - 1
        });
        region
            .assign_advice(|| "r", self.r_decompose.word, offset, || Value::known(r))
            .unwrap();
        self.r_decompose.assign_decompose(region, r, offset);
    }
}

fn eval_constraints<const WORD_BITS: u32, F: FieldExt>(
    a: i128,
    b: i128,
    c: i128,
    d: i128,
) {
    let a_shift = WORD_BITS < a as _;
    dbg!(a_shift);
    let a_power = if a_shift {
        0
    } else {
        2u64.pow(a.try_into().unwrap()) % 2u64.pow(WORD_BITS)
    };
    dbg!(a_power);

    let r = if c == 0 { 0 } else { c - a - 1 };
    dbg!(r);

    assert!(a <= u32::MAX.into());

    let a_shift = a_shift as i128;
    let a_power = a_power as i128;
    let r = r as i128;

    let (r_e, r_o) = even_bits::decompose(f_from_i128::<F>(r));
    let r_e: i128 = r_e.0.get_lower_128().try_into().unwrap();
    let r_o: i128 = r_o.0.get_lower_128().try_into().unwrap();

    assert_eq!(0, (1 - a_shift) * (WORD_BITS as i128 - a - (2 * r_o) - r_e));
    eprintln!("a_shift is a bool: {}", a_shift * (a_shift - 1));
    eprintln!(
        "Part of FLAG4: {}",
        (1 - a_shift) * (WORD_BITS as i128 - a - (2 * r_o) - r_e)
    );
    eprintln!(
        "Part of FLAG4 = (1 - a_shift: {}) * (WORD_BITS: {} - a: {} - (2 * r_o: {}) - r_e: {})",
        a_shift, WORD_BITS, a, r_o, r_e
    );
    eprintln!("SHIFT: {}", a_power * b - d - (2i128.pow(WORD_BITS) * c));
    eprintln!(
        "SHIFT = a_power {} * b: {} - d: {} - (2^W: {} * c:{})",
        a_power,
        b,
        d,
        2i128.pow(WORD_BITS),
        c
    );
}

fn f_from_i128<F: FieldExt>(n: i128) -> F {
    if n < 0 {
        -F::from_u128((-n).try_into().unwrap())
    } else {
        F::from_u128(n.try_into().unwrap())
    }
}

pub fn non_det_d<const WORD_BITS: u32, F: FieldExt>(a: u128, b: u128, d: u128) -> F {
    let a = i128::try_from(a).unwrap();
    let b = i128::try_from(b).unwrap();
    let c = i128::try_from(d).unwrap();

    let a_shift = WORD_BITS < a as _;
    dbg!(a_shift);
    let a_power = if a_shift {
        0
    } else {
        2u64.pow(a.try_into().unwrap()) % 2u64.pow(WORD_BITS)
    };
    dbg!(a_power);

    let r = if a > WORD_BITS as _ {
        0
    } else {
        assert!(a >= 0);
        WORD_BITS as i128 - a
    };
    dbg!(r);

    assert!(a <= u32::MAX.into());

    let d =
        (2i128.pow((a) as _)) * (b as i128) - ((2i128.pow(WORD_BITS)) * (c as i128));
    eprintln!("a: {}, b: {}, c: {}, d: {}", a, b, c, d);
    eval_constraints::<WORD_BITS, F>(a, b, c, d);

    let d: i128 = truncate::<WORD_BITS>(
        (2i128.pow(a.try_into().unwrap()) * b).try_into().unwrap(),
    )
    .0
    .try_into()
    .unwrap();
    eprintln!("a: {}, b: {}, c: {}, d: {}", a, b, c, d);
    eval_constraints::<WORD_BITS, F>(a, b, c, d);

    // assert!(d < 2i128.pow(WORD_BITS));
    // F::from(u64::try_from(d).unwrap())
    f_from_i128(d)
}

pub fn non_det_c<const WORD_BITS: u32, F: FieldExt>(a: i128, b: i128, d: i128) -> F {
    F::from_u128(
        ((2i128.pow(a as _) * b - d) / 2i128.pow(WORD_BITS))
            .try_into()
            .unwrap(),
    )
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
pub struct ShiftCircuit<F: FieldExt, const WORD_BITS: u32, const SHIFT_RIGHT: bool> {
    /// b
    pub word: Option<F>,
    /// a
    pub shift_bits: Option<F>,
}

impl<const WORD_BITS: u32, const SHIFT_RIGHT: bool> Circuit<Fp>
    for ShiftCircuit<Fp, WORD_BITS, SHIFT_RIGHT>
{
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
        let d = meta.advice_column();

        // b is right shifts result
        // d is left shifts result
        meta.enable_equality(b);
        meta.enable_equality(d);

        // Overflow flag
        let flag = meta.advice_column();
        meta.enable_equality(flag);

        let even_bits = EvenBitsTable::new(meta);

        let a_shift = meta.advice_column();
        let a_power = meta.advice_column();
        let r_decompose = meta.advice_column();
        let r_decompose = EvenBitsConfig::configure(
            meta,
            r_decompose,
            &[s_shift],
            s_table,
            even_bits,
        );

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
                a_shift,
                a_power,
                r_decompose,
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
        config.0.pow.alloc_table(&mut layouter).unwrap();
        config
            .0
            .r_decompose
            .even_bits
            .alloc_table(&mut layouter)
            .unwrap();
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
                    if self.word.is_some() || self.shift_bits.is_some() {
                        // load private
                        let a = self.shift_bits.unwrap();

                        region
                            .assign_advice(|| "a", config.0.a, 0, || Value::known(a))
                            .unwrap();

                        {
                            let a = a.get_lower_128();

                            let (b, c, d) = if SHIFT_RIGHT {
                                let d: u128 = self.word.unwrap().get_lower_128();
                                let b: u128 = truncate::<WORD_BITS>(
                                    d >> self.shift_bits.unwrap().get_lower_128(),
                                )
                                .0
                                .into();

                                let (c, d_check) = {
                                    let out = 2u128.pow(a.try_into().unwrap()) * b;
                                    (
                                        out & get_word_size_bit_mask_msb(WORD_BITS),
                                        out & ((2u128.pow(WORD_BITS)) - 1),
                                    )
                                };

                                // eval_constraints::<WORD_BITS, Fp>(
                                //     a.try_into().unwrap(),
                                //     b.try_into().unwrap(),
                                //     c.try_into().unwrap(),
                                //     d.try_into().unwrap(),
                                // );
                                // eval_constraints::<WORD_BITS, Fp>(
                                //     a.try_into().unwrap(),
                                //     b.try_into().unwrap(),
                                //     c.try_into().unwrap(),
                                //     d_check.try_into().unwrap(),
                                // );
                                assert_eq!(d, d_check);
                                (
                                    Fp::from_u128(b),
                                    Fp::from_u128(c),
                                    Fp::from_u128(d),
                                )
                            } else {
                                let b = self.word.unwrap().get_lower_128();
                                let d = (b
                                    << self.shift_bits.unwrap().get_lower_128())
                                    & ((2u128.pow(WORD_BITS)) - 1);

                                let c = non_det_c::<WORD_BITS, Fp>(
                                    a.try_into().unwrap(),
                                    b.try_into().unwrap(),
                                    d.try_into().unwrap(),
                                );
                                (Fp::from_u128(b), c, Fp::from_u128(d))
                            };

                            region
                                .assign_advice(
                                    || "b",
                                    config.0.b,
                                    0,
                                    || Value::known(b),
                                )
                                .unwrap();

                            region
                                .assign_advice(
                                    || "c",
                                    config.0.c,
                                    0,
                                    || Value::known(c),
                                )
                                .unwrap();

                            region
                                .assign_advice(
                                    || "d",
                                    config.0.d,
                                    0,
                                    || Value::known(d),
                                )
                                .unwrap();

                            config.0.assign_shift(
                                &mut region,
                                a,
                                c.get_lower_128(),
                                0,
                            );
                        };

                        if SHIFT_RIGHT {
                            let a = a.get_lower_128();
                            let d = self.word.unwrap();
                            region
                                .assign_advice(
                                    || "d",
                                    config.0.d,
                                    0,
                                    || Value::known(d),
                                )
                                .unwrap();
                            let d = d.get_lower_128();

                            let b: u128 = truncate::<WORD_BITS>(
                                d >> self.shift_bits.unwrap().get_lower_128(),
                            )
                            .0
                            .try_into()
                            .unwrap();

                            let out = 2u128.pow(a.try_into().unwrap()) * b;
                            let out_l = dbg!(truncate::<WORD_BITS>(out));
                            let out_h =
                                dbg!(out & get_word_size_bit_mask_msb(WORD_BITS));
                            assert_eq!(u128::from(out_l.0), d);
                            let c = out_h.try_into().unwrap();

                            let a = i128::try_from(a).unwrap();
                            // let d = i128::try_from(d).unwrap()

                            let a_shift = WORD_BITS < a as _;
                            dbg!(a_shift);
                            let a_power = if a_shift {
                                0
                            } else {
                                2u64.pow(a.try_into().unwrap()) % 2u64.pow(WORD_BITS)
                            };
                            dbg!(a_power);

                            let r = if c == 0 { 0 } else { c - a - 1 };
                            dbg!(r);

                            let a = WORD_BITS as i128 - a;
                            eval_constraints::<WORD_BITS, Fp>(
                                a,
                                b.try_into().unwrap(),
                                c,
                                d.try_into().unwrap(),
                            );

                            region
                                .assign_advice(
                                    || "b",
                                    config.0.b,
                                    0,
                                    || Value::known(Fp::from_u128(b)),
                                )
                                .unwrap();

                            region
                                .assign_advice(
                                    || "c",
                                    config.0.c,
                                    0,
                                    || Value::known(Fp::from_u128(c.try_into().unwrap())),
                                )
                                .unwrap();

                            region
                                .assign_advice(
                                    || "d",
                                    config.0.d,
                                    0,
                                    || Value::known(Fp::from_u128(d)),
                                )
                                .unwrap();

                            config.0.assign_shift(
                                &mut region,
                                a.try_into().unwrap(),
                                c.try_into().unwrap(),
                                0,
                            );
                        }
                        //         } else {
                        //             // shift left

                        //             let b = self.word.unwrap();
                        //             region
                        //                 .assign_advice(
                        //                     || "b",
                        //                     config.0.b,
                        //                     0,
                        //                     || Value::known(b),
                        //                 )
                        //                 .unwrap();

                        //             let b = b.get_lower_128();
                        //             let d: u128 = truncate::<WORD_BITS>(
                        //                 b << self.shift_bits.unwrap().get_lower_128(),
                        //             )
                        //             .0
                        //             .into();
                        //             region
                        //                 .assign_advice(
                        //                     || "c",
                        //                     config.0.c,
                        //                     0,
                        //                     || {
                        //                         Value::known(non_det_c::<WORD_BITS, Fp>(
                        //                             a.try_into().unwrap(),
                        //                             b.try_into().unwrap(),
                        //                             d.try_into().unwrap(),
                        //                         ))
                        //                     },
                        //                 )
                        //                 .unwrap();
                        //         }
                        //     }
                        //     }
                    }

                    region
                        .assign_advice_from_instance(
                            || "res",
                            config.1,
                            0,
                            // if SHIFT_RIGHT { config.0.c } else { config.0.d },
                            if SHIFT_RIGHT { config.0.b } else { config.0.d },
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
      fn valid_values(word_bits: u32, right_shift: bool)
              (word in 0..2u64.pow(word_bits), shift_bits in 0..(word_bits))
              -> (u64, u64, u64, bool) {
        let (shift_bits, out) = if right_shift {
            (
                // word_bits - shift_bits,
                shift_bits,
                (word >> shift_bits) & ((2u64.pow(word_bits)) - 1),
            )
        } else {
            (
                shift_bits,
                (word << shift_bits) & ((2u64.pow(word_bits)) - 1),
            )
        };

        (shift_bits as _, word, out, false)
      }
    }

    fn shift<const WORD_BITS: u32, const SHIFT_RIGHT: bool>(
        v: Vec<(u64, u64, u64, bool)>,
    ) -> Vec<(ShiftCircuit<Fp, WORD_BITS, SHIFT_RIGHT>, Vec<Vec<Fp>>)> {
        v.into_iter()
            .map(|(shift_bits, word, out, flag)| {
                (
                    ShiftCircuit {
                        word: Some(word.into()),
                        shift_bits: Some(shift_bits.into()),
                    },
                    vec![vec![out.into(), flag.into()]],
                )
            })
            .collect()
    }

    mod left {
        use super::*;
        proptest! {
            /// proptest does not support testing const generics.
            #[test]
            fn all_8_bit_words_mock_prover_test((a, b, c, flag) in valid_values(8, false)) {
                mock_prover_test::<8, false>(a, b, c, flag)
            }
        }

        proptest! {
            #![proptest_config(ProptestConfig {
              cases: 20, .. ProptestConfig::default()
            })]

            #[test]
            fn all_8_bit_words_test(s in prop::collection::vec(valid_values(8, false), 10)) {
                gen_proofs_and_verify::<8, _>(shift::<8, false>(s))
            }

            #[test]
            fn all_16_bit_words_mock_prover_test((a, b, c, flag) in valid_values(16, false)) {
                mock_prover_test::<16, false>(a, b, c, flag)
            }

            #[test]
            fn all_16_bit_words_test(s in prop::collection::vec(valid_values(16, false), 10)) {
                gen_proofs_and_verify::<16, _>(shift::<16, false>(s))
            }

            #[test]
            fn all_8_bit_words_test_bad_proof(word in 0..2u64.pow(8), shift_bits in 0..8u64, c in 0..2u64.pow(8), flag: bool) {
                prop_assume!((c != word << shift_bits));
                let circuit = ShiftCircuit::<Fp, 8, false> {word: Some(word.into()), shift_bits: Some(shift_bits.into())};
                gen_proofs_and_verify_should_fail::<8, _>(circuit, vec![c.into(), flag.into()])
            }
        }

        proptest! {
            // The case number was picked to run all tests in about 60 seconds on my machine.
            #![proptest_config(ProptestConfig {
              cases: 10, .. ProptestConfig::default()
            })]

            #[test]
            fn all_24_bit_words_mock_prover_test((a, b, c, flag) in valid_values(24, false)) {
                mock_prover_test::<24, false>(a, b, c, flag)
            }

            #[test]
            fn all_24_bit_words_test(s in prop::collection::vec(valid_values(24, false), 10)) {
                gen_proofs_and_verify::<24, _>(shift::<24, false>(s))
            }
        }
    }

    mod right {
        use super::*;

        #[test]
        fn mock_prover_test_0_1_1_false() {
            mock_prover_test::<8, true>(0, 1, 1, false)
        }

        proptest! {
            /// proptest does not support testing const generics.
            #[test]
            fn all_8_bit_words_mock_prover_test((a, b, c, flag) in valid_values(8, true)) {
                mock_prover_test::<8, true>(a, b, c, flag)
            }
        }

        proptest! {
            #![proptest_config(ProptestConfig {
              cases: 20, .. ProptestConfig::default()
            })]

            #[test]
            fn all_8_bit_words_test(s in prop::collection::vec(valid_values(8, true), 10)) {
                gen_proofs_and_verify::<8, _>(shift::<8, true>(s))
            }

            #[test]
            fn all_16_bit_words_mock_prover_test((a, b, c, flag) in valid_values(16, true)) {
                mock_prover_test::<16, true>(a, b, c, flag)
            }

            #[test]
            fn all_16_bit_words_test(s in prop::collection::vec(valid_values(16, true), 10)) {
                gen_proofs_and_verify::<16, _>(shift::<16, true>(s))
            }

            #[test]
            fn all_8_bit_words_test_bad_proof(word in 0..2u64.pow(8), shift_bits in 0..8u64, c in 0..2u64.pow(8), flag: bool) {
                prop_assume!((c != word >> shift_bits));
                let circuit = ShiftCircuit::<Fp, 8, true> {word: Some(word.into()), shift_bits: Some(shift_bits.into())};
                gen_proofs_and_verify_should_fail::<8, _>(circuit, vec![c.into(), flag.into()])
            }
        }

        proptest! {
            // The case number was picked to run all tests in about 60 seconds on my machine.
            #![proptest_config(ProptestConfig {
              cases: 10, .. ProptestConfig::default()
            })]

            #[test]
            fn all_24_bit_words_mock_prover_test((a, b, c, flag) in valid_values(24, true)) {
                mock_prover_test::<24, true>(a, b, c, flag)
            }

            #[test]
            fn all_24_bit_words_test(s in prop::collection::vec(valid_values(24, true), 10)) {
                gen_proofs_and_verify::<24, _>(shift::<24, true>(s))
            }
        }
    }

    // It's used in the proptests
    fn mock_prover_test<const WORD_BITS: u32, const SHIFT_RIGHT: bool>(
        a: u64,
        b: u64,
        c: u64,
        flag: bool,
    ) {
        let k = 1 + WORD_BITS / 2;
        let circuit: ShiftCircuit<Fp, WORD_BITS, SHIFT_RIGHT> = ShiftCircuit {
            word: Some(Fp::from(b)),
            shift_bits: Some(Fp::from(a)),
        };

        let prover =
            MockProver::run(k, &circuit, vec![vec![c.into(), flag.into()]]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }
}
