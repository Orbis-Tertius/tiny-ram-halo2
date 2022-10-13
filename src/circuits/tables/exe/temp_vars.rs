use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Region, Value},
    plonk::{Advice, Column, Selector},
};

use crate::{
    assign::ConstraintSys,
    circuits::tables::{
        aux::{out::Out, TempVarSelectors},
        even_bits::{EvenBitsConfig, EvenBitsTable},
    },
};

/// The temporary variables, and their decompositions which always exist (namely even bits).
/// Other decompositions like `SignedConfig` only exist for lines of Exe containing an instruction
/// that uses the decomposition.
///
/// The even bits decomposition is enforced on all lines of Exe for every temporary variable.
/// The temporary variable columns are stored at `EvenBitsConfig.word`.
#[derive(Debug, Clone, Copy)]
pub struct TempVars<const WORD_BITS: u32> {
    pub a: EvenBitsConfig<WORD_BITS>,
    pub b: EvenBitsConfig<WORD_BITS>,
    pub c: EvenBitsConfig<WORD_BITS>,
    pub d: EvenBitsConfig<WORD_BITS>,
}

impl<const WORD_BITS: u32> TempVars<WORD_BITS> {
    /// `s_table` defines the maxium extent of the Exe table.
    /// `time` counts from 1, and is zero padded.
    /// `time` defines the used portion of the table in which the decompositions are enforced
    pub fn configure<const REG_COUNT: usize, F: FieldExt>(
        meta: &mut impl ConstraintSys<F, Column<Advice>>,
        // A complex selector denoting the extent in rows of the table to decompse.
        s_table: Selector,
        temp_var_selectors: TempVarSelectors<REG_COUNT, Column<Advice>>,
        even_bits: EvenBitsTable<WORD_BITS>,
    ) -> Self {
        // Temporary vars
        //
        // By using `meta.cs().advice_column()` instead of `meta.new_column()`
        // we exclude temporary variables columns from `TrackColumns`.
        let a = meta.cs().advice_column();
        let b = meta.cs().advice_column();
        let c = meta.cs().advice_column();
        let d = meta.cs().advice_column();

        // In the future we may want to optimize column count by reusing `EvenBitsConfig{even, odd}`.
        // The table below describes when eacj decomposition is in use.

        let TempVarSelectors {
            out:
                Out {
                    and,
                    xor,
                    or,
                    sum,
                    ssum,
                    prod,
                    sprod,
                    mod_,
                    shift,
                    flag4,
                    ..
                },
            ..
        } = temp_var_selectors;

        // Constraints which rely on a's even_bits decomposition:
        // MOD (UDiv non_det must be valid word)
        // AND, OR, XOR (`LogicConfig`)
        // SSUM, SPROD (`signed_a`)
        let a = EvenBitsConfig::configure(
            meta,
            a,
            &[mod_, and, or, xor, ssum, sprod],
            s_table,
            even_bits,
        );

        // Constraints which rely on b's even_bits decomposition:
        // MOD (UMod non_det must be valid word)
        // SUM (Cmpa, Cmpae non_det must be valid word)
        // SSUM (Cmpge, Cmpg non_det must be valid word)
        // SPROD, FLAG4 (`signed_b`)
        //
        // SHIFT can be active with FLAG4,
        let b = EvenBitsConfig::configure(
            meta,
            b,
            &[mod_, sum, ssum, sprod, flag4],
            s_table,
            even_bits,
        );

        // Constraints which rely on c's even_bits decomposition:
        // XOR (Cmpe non_det must be valid word)
        // PROD (Mull non_det must be valid word)
        // SHIFT (Shl non_det must be valid word)
        // SSUM, SPROD (`signed_c`)
        let c = EvenBitsConfig::configure(
            meta,
            c,
            &[xor, prod, shift, ssum, sprod],
            s_table,
            even_bits,
        );

        // Constraints which rely on d's even_bits decomposition:
        // SHIFT (Shr non_det must be valid word)
        // PROD (UMulh non_det must be valid word)
        // SPROD (SMulh on_det must be valid word)
        let d = EvenBitsConfig::configure(
            meta,
            d,
            // FIXME enforce on shift
            // &[shift, prod, sprod],
            &[prod, sprod],
            s_table,
            even_bits,
        );

        TempVars { a, b, c, d }
    }

    pub fn assign_temp_vars<F: FieldExt>(
        &self,
        region: &mut Region<'_, F>,
        a: F,
        b: F,
        c: F,
        d: F,
        offset: usize,
    ) {
        region
            .assign_advice(
                || format!("a: {:?}", a),
                self.a.word,
                offset,
                || Value::known(a),
            )
            .unwrap();
        self.a.assign_decompose(region, a, offset);

        region
            .assign_advice(
                || format!("b: {:?}", b),
                self.b.word,
                offset,
                || Value::known(b),
            )
            .unwrap();
        self.b.assign_decompose(region, b, offset);

        region
            .assign_advice(
                || format!("c: {:?}", c),
                self.c.word,
                offset,
                || Value::known(c),
            )
            .unwrap();
        self.c.assign_decompose(region, c, offset);

        region
            .assign_advice(
                || format!("d: {:?}", d),
                self.d.word,
                offset,
                || Value::known(d),
            )
            .unwrap();
        self.d.assign_decompose(region, d, offset);
    }
}
