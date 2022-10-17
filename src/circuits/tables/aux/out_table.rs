use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Layouter, Table, Value},
    plonk::{
        Advice, Column, ConstraintSystem, Error, Expression, Selector, TableColumn,
    },
    poly::Rotation,
};

use super::out::{Out, OutPut};
use crate::instructions::{opcode::OpCode, *};

#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
pub struct CorrectOutConfig {
    opcode: Column<Advice>,
    out: Out<Column<Advice>>,
    out_table: OutTable,
}

impl CorrectOutConfig {
    /// configure a lookup between opcode, and Out selection vector.
    pub fn configure<F: FieldExt>(
        meta: &mut ConstraintSystem<F>,
        opcode: Column<Advice>,
        out: Out<Column<Advice>>,
        // A advice selector denoting if a line of Exe is part of the trace.
        s_correct_out: Column<Advice>,
        // A complex selector denoting the extent in rows of the table to decompose.
        s_table: Selector,
    ) -> Self {
        let out_table = OutTable::new(meta);

        meta.lookup(|meta| {
            let s_table = meta.query_selector(s_table);
            let s_correct_out = meta.query_advice(s_correct_out, Rotation::cur());
            let opcode = meta.query_advice(opcode, Rotation::cur());
            let Out {
                and,
                xor,
                or,
                sum,
                ssum,
                prod,
                sprod,
                mod_,
                shift,
                flag1,
                flag2,
                flag3,
                flag4,
            } = out.map(|c| meta.query_advice(c, Rotation::cur()));

            [
                // For an explanation of `opcode + 1` the comment on `OutTable`.
                (opcode + Expression::Constant(F::one()), out_table.opcode),
                (and, out_table.out.and),
                (xor, out_table.out.xor),
                (or, out_table.out.or),
                (sum, out_table.out.sum),
                (ssum, out_table.out.ssum),
                (prod, out_table.out.prod),
                (sprod, out_table.out.sprod),
                (mod_, out_table.out.mod_),
                (shift, out_table.out.shift),
                (flag1, out_table.out.flag1),
                (flag2, out_table.out.flag2),
                (flag3, out_table.out.flag3),
                (flag4, out_table.out.flag4),
            ]
            .map(|(e, t)| (s_table.clone() * s_correct_out.clone() * e, t))
            .to_vec()
        });

        Self {
            opcode,
            out,
            out_table,
        }
    }
}

/// The table maps `opcode + 1` to the opcode's `Out` selection vector.
/// `opcode + 1` is used to give a default mapping `(opcode * 0, Out * 0)`.
/// This increment is hidden from the user in the `configure` method.
#[derive(Debug, Clone, Copy)]
pub struct OutTable {
    opcode: TableColumn,
    out: Out<TableColumn>,
}

impl OutTable {
    pub fn new<F: FieldExt>(meta: &mut ConstraintSystem<F>) -> Self {
        OutTable {
            opcode: meta.lookup_table_column(),
            out: Out::new(|| meta.lookup_table_column()),
        }
    }

    fn assign_row<F: FieldExt>(
        &self,
        table: &mut Table<'_, F>,
        offset: usize,
        opcode: u64,
        out: Out<bool>,
    ) {
        table
            .assign_cell(
                || "",
                self.opcode,
                offset,
                || Value::known(F::from(opcode)),
            )
            .unwrap();
        self.out.push_cells(&mut (table, offset), out).unwrap();
    }

    pub fn alloc_table<F: FieldExt>(
        self,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        layouter.assign_table(
            || "even bits",
            |mut table| {
                self.assign_row(
                    &mut table,
                    0,
                    And::<(), ()>::OP_CODE + 1,
                    And::<(), ()>::OUT,
                );
                self.assign_row(
                    &mut table,
                    1,
                    Or::<(), ()>::OP_CODE + 1,
                    Or::<(), ()>::OUT,
                );
                self.assign_row(
                    &mut table,
                    2,
                    Xor::<(), ()>::OP_CODE + 1,
                    Xor::<(), ()>::OUT,
                );
                self.assign_row(
                    &mut table,
                    3,
                    Not::<(), ()>::OP_CODE + 1,
                    Not::<(), ()>::OUT,
                );
                self.assign_row(
                    &mut table,
                    4,
                    Add::<(), ()>::OP_CODE + 1,
                    Add::<(), ()>::OUT,
                );
                self.assign_row(
                    &mut table,
                    5,
                    Sub::<(), ()>::OP_CODE + 1,
                    Sub::<(), ()>::OUT,
                );
                self.assign_row(
                    &mut table,
                    6,
                    Mull::<(), ()>::OP_CODE + 1,
                    Mull::<(), ()>::OUT,
                );
                self.assign_row(
                    &mut table,
                    7,
                    UMulh::<(), ()>::OP_CODE + 1,
                    UMulh::<(), ()>::OUT,
                );
                self.assign_row(
                    &mut table,
                    8,
                    SMulh::<(), ()>::OP_CODE + 1,
                    SMulh::<(), ()>::OUT,
                );
                self.assign_row(
                    &mut table,
                    9,
                    UDiv::<(), ()>::OP_CODE + 1,
                    UDiv::<(), ()>::OUT,
                );
                self.assign_row(
                    &mut table,
                    10,
                    UMod::<(), ()>::OP_CODE + 1,
                    UMod::<(), ()>::OUT,
                );
                self.assign_row(
                    &mut table,
                    11,
                    Shl::<(), ()>::OP_CODE + 1,
                    Shl::<(), ()>::OUT,
                );
                self.assign_row(
                    &mut table,
                    12,
                    Shr::<(), ()>::OP_CODE + 1,
                    Shr::<(), ()>::OUT,
                );
                self.assign_row(
                    &mut table,
                    13,
                    Cmpe::<(), ()>::OP_CODE + 1,
                    Cmpe::<(), ()>::OUT,
                );
                self.assign_row(
                    &mut table,
                    14,
                    Cmpa::<(), ()>::OP_CODE + 1,
                    Cmpa::<(), ()>::OUT,
                );
                self.assign_row(
                    &mut table,
                    15,
                    Cmpae::<(), ()>::OP_CODE + 1,
                    Cmpae::<(), ()>::OUT,
                );
                self.assign_row(
                    &mut table,
                    16,
                    Cmpg::<(), ()>::OP_CODE + 1,
                    Cmpg::<(), ()>::OUT,
                );
                self.assign_row(
                    &mut table,
                    17,
                    Cmpge::<(), ()>::OP_CODE + 1,
                    Cmpge::<(), ()>::OUT,
                );
                self.assign_row(
                    &mut table,
                    18,
                    Mov::<(), ()>::OP_CODE + 1,
                    Mov::<(), ()>::OUT,
                );
                self.assign_row(
                    &mut table,
                    19,
                    CMov::<(), ()>::OP_CODE + 1,
                    CMov::<(), ()>::OUT,
                );
                self.assign_row(
                    &mut table,
                    20,
                    Jmp::<()>::OP_CODE + 1,
                    Jmp::<()>::OUT,
                );
                self.assign_row(
                    &mut table,
                    21,
                    CJmp::<()>::OP_CODE + 1,
                    CJmp::<()>::OUT,
                );
                self.assign_row(
                    &mut table,
                    22,
                    CnJmp::<()>::OP_CODE + 1,
                    CnJmp::<()>::OUT,
                );
                self.assign_row(
                    &mut table,
                    23,
                    StoreW::<(), ()>::OP_CODE + 1,
                    StoreW::<(), ()>::OUT,
                );
                self.assign_row(
                    &mut table,
                    24,
                    LoadW::<(), ()>::OP_CODE + 1,
                    LoadW::<(), ()>::OUT,
                );
                self.assign_row(
                    &mut table,
                    25,
                    Answer::<()>::OP_CODE + 1,
                    Answer::<()>::OUT,
                );
                Ok(())
            },
        )
    }
}
