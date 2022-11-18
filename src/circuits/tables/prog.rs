use std::fmt::Debug;

use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Layouter, Value},
    plonk::{
        Advice, Column, ConstraintSystem, DynamicTable, DynamicTableMap, Error,
        Fixed, Instance, Selector,
    },
    poly::Rotation,
};

use crate::{
    assign::{AssignCell, NewColumn, PseudoColumn, PseudoMeta},
    instructions::Instruction,
    trace,
};

use super::aux::{TempVarSelectors, TempVarSelectorsRow};

#[derive(Debug, Clone, Copy)]
pub struct ProgramLine<const WORD_BITS: u32, const REG_COUNT: usize, C: Copy> {
    pub opcode: C,
    pub immediate: C,
    pub temp_var_selectors: TempVarSelectors<REG_COUNT, C>,
}

#[derive(Debug, Clone, Copy)]
pub struct ProgConfig<const WORD_BITS: u32, const REG_COUNT: usize> {
    s_prog: Selector,
    input: ProgramLine<WORD_BITS, REG_COUNT, Column<Instance>>,

    dyn_table: DynamicTable,
    table: ProgramLine<WORD_BITS, REG_COUNT, Column<Advice>>,
    pc: Column<Fixed>,
}

pub fn program_instance<
    const WORD_BITS: u32,
    const REG_COUNT: usize,
    F: FieldExt,
>(
    mut program: trace::Program,
) -> Vec<Vec<F>> {
    let max_program_len = ProgConfig::<WORD_BITS, REG_COUNT>::TABLE_LEN;
    let last_inst = *program.0.last().expect("Empty programs are invalid");
    assert!(matches!(last_inst, Instruction::Answer(_)));
    assert!(program.0.len() <= max_program_len);

    for _ in 0..(max_program_len - program.0.len()) {
        // Fill the remainder of the program space by repeating the terminal instruction (Answer).
        program.0.push(last_inst);
    }

    let mut meta = PseudoMeta::default();
    let input_cols: ProgramLine<WORD_BITS, REG_COUNT, PseudoColumn> =
        ProgramLine::configure::<F, _>(&mut meta);
    input_cols.assign_cells(&mut meta, &program);
    meta.0
}

impl<const WORD_BITS: u32, const REG_COUNT: usize, C: Copy + Debug>
    ProgramLine<WORD_BITS, REG_COUNT, C>
{
    pub fn configure<F: FieldExt, M: NewColumn<C>>(
        meta: &mut M,
    ) -> ProgramLine<WORD_BITS, REG_COUNT, C> {
        let opcode = meta.new_column();
        let immediate = meta.new_column();
        let temp_vars = TempVarSelectors::new::<F, M>(meta);

        ProgramLine {
            opcode,
            immediate,
            temp_var_selectors: temp_vars,
        }
    }

    pub fn assign_cells<F: FieldExt, R: AssignCell<F, C>>(
        self,
        region: &mut R,
        program: &trace::Program,
    ) {
        let ProgramLine {
            opcode,
            immediate,
            temp_var_selectors,
        } = self;

        for (offset, inst) in program.0.iter().enumerate() {
            region
                .assign_cell(opcode, offset, F::from_u128(inst.opcode()))
                .unwrap();
            region
                .assign_cell(
                    immediate,
                    offset,
                    F::from_u128(inst.a().immediate().unwrap_or_default().into()),
                )
                .unwrap();
            temp_var_selectors.assign_cells(
                region,
                offset,
                TempVarSelectorsRow::from(inst),
            );
        }
    }

    pub fn map<B: Copy>(
        self,
        mut f: impl FnMut(C) -> B,
    ) -> ProgramLine<WORD_BITS, REG_COUNT, B> {
        let Self {
            opcode,
            immediate,
            temp_var_selectors,
        } = self;

        ProgramLine {
            opcode: f(opcode),
            immediate: f(immediate),
            temp_var_selectors: temp_var_selectors.map(f),
        }
    }

    pub fn to_vec(self) -> Vec<C> {
        let mut v = Vec::with_capacity(30);
        self.map(|c| v.push(c));
        v
    }
}

impl<const WORD_BITS: u32, const REG_COUNT: usize> ProgConfig<WORD_BITS, REG_COUNT> {
    /// Currently this is the same as `ExeConfig::TABLE_LEN`.
    /// Programs will usually be much smaller than traces,
    /// so we should reduce this to allow stacking.
    const TABLE_LEN: usize = 2usize.pow(WORD_BITS / 2);

    pub fn configure<F: FieldExt>(meta: &mut ConstraintSystem<F>) -> Self {
        let s_prog = meta.selector();
        let input = ProgramLine::configure::<F, _>(meta);

        let table = ProgramLine::configure::<F, _>(meta);
        let pc = meta.fixed_column();
        let dyn_table = meta.create_dynamic_table(
            "Prog Table",
            &[pc],
            table.to_vec().as_slice(),
        );

        input.map(|c| meta.enable_equality(c));
        table.map(|c| meta.enable_equality(c));

        Self {
            s_prog,
            input,
            dyn_table,
            table,
            pc,
        }
    }

    pub fn lookup<F: FieldExt>(
        &self,
        meta: &mut ConstraintSystem<F>,
        s_trace: Column<Advice>,
        pc: Column<Advice>,
        exe_line: ProgramLine<WORD_BITS, REG_COUNT, Column<Advice>>,
    ) {
        meta.lookup_dynamic(&self.dyn_table, |meta| {
            let s_trace = meta.query_advice(s_trace, Rotation::cur());

            let pc = meta.query_advice(pc, Rotation::cur());
            let mut table_map = vec![(pc, self.pc.into())];
            table_map.extend(
                exe_line
                    .to_vec()
                    .into_iter()
                    .zip(self.table.to_vec().into_iter())
                    .map(|(exe_col, prog_col)| {
                        (
                            meta.query_advice(exe_col, Rotation::cur()),
                            prog_col.into(),
                        )
                    }),
            );

            DynamicTableMap {
                selector: s_trace,
                table_map,
            }
        });
    }

    pub fn assign_prog<F: FieldExt>(
        self,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "Prog",
            |mut region| {
                let input_cols = self.input.to_vec();
                let table_cols = self.table.to_vec();

                for (ic, tc) in input_cols.into_iter().zip(table_cols.into_iter()) {
                    for offset in 0..Self::TABLE_LEN {
                        region.assign_advice_from_instance(
                            || "",
                            ic,
                            offset,
                            tc,
                            offset,
                        )?;
                    }
                }

                for offset in 0..Self::TABLE_LEN {
                    self.s_prog.enable(&mut region, offset)?;
                    self.dyn_table.add_row(&mut region, offset)?;
                    region.assign_fixed(
                        || "pc",
                        self.pc,
                        offset,
                        || Value::known(F::from(offset as u64)),
                    )?;
                }

                Ok(())
            },
        )?;

        Ok(())
    }
}
