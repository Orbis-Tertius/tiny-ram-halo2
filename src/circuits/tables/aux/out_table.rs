use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Layouter, Table, Value},
    plonk::{ConstraintSystem, Error, TableColumn, Column, Advice},
};

use super::out::{Out, OutPut};
use crate::instructions::{opcode::OpCode, *};

#[derive(Debug, Clone, Copy)]
pub struct CorrectOutConfig {
    opcode: Column<Advice>,
    out: Out<Column<Advice>>,
}

impl CorrectOutConfig {
    
    pub fn configure<F: FieldExt>(
        meta: &mut ConstraintSystem<F>,
        opcode: Column<Advice>,
        s_even_bits: &[Column<Advice>],
        // A complex selector denoting the extent in rows of the table to decompse.
        s_table: Selector,
        even_bits: EvenBitsTable<WORD_BITS>,
    ) -> Self {
}

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
        table.assign_cell(
            || "",
            self.opcode,
            offset,
            || Value::known(F::from(opcode)),
        ).unwrap();
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
                    And::<(), ()>::OP_CODE,
                    And::<(), ()>::OUT,
                );
                self.assign_row(
                    &mut table,
                    1,
                    Or::<(), ()>::OP_CODE,
                    Or::<(), ()>::OUT,
                );
                self.assign_row(
                    &mut table,
                    2,
                    Xor::<(), ()>::OP_CODE,
                    Xor::<(), ()>::OUT,
                );
                self.assign_row(
                    &mut table,
                    3,
                    Not::<(), ()>::OP_CODE,
                    Not::<(), ()>::OUT,
                );
                self.assign_row(
                    &mut table,
                    4,
                    Add::<(), ()>::OP_CODE,
                    Add::<(), ()>::OUT,
                );
                self.assign_row(
                    &mut table,
                    5,
                    Sub::<(), ()>::OP_CODE,
                    Sub::<(), ()>::OUT,
                );
                self.assign_row(
                    &mut table,
                    6,
                    Mull::<(), ()>::OP_CODE,
                    Mull::<(), ()>::OUT,
                );
                self.assign_row(
                    &mut table,
                    7,
                    UMulh::<(), ()>::OP_CODE,
                    UMulh::<(), ()>::OUT,
                );
                self.assign_row(
                    &mut table,
                    8,
                    SMulh::<(), ()>::OP_CODE,
                    SMulh::<(), ()>::OUT,
                );
                self.assign_row(
                    &mut table,
                    9,
                    UDiv::<(), ()>::OP_CODE,
                    UDiv::<(), ()>::OUT,
                );
                self.assign_row(
                    &mut table,
                    10,
                    UMod::<(), ()>::OP_CODE,
                    UMod::<(), ()>::OUT,
                );
                self.assign_row(
                    &mut table,
                    11,
                    Shl::<(), ()>::OP_CODE,
                    Shl::<(), ()>::OUT,
                );
                self.assign_row(
                    &mut table,
                    12,
                    Shr::<(), ()>::OP_CODE,
                    Shr::<(), ()>::OUT,
                );
                self.assign_row(
                    &mut table,
                    13,
                    Cmpe::<(), ()>::OP_CODE,
                    Cmpe::<(), ()>::OUT,
                );
                self.assign_row(
                    &mut table,
                    14,
                    Cmpa::<(), ()>::OP_CODE,
                    Cmpa::<(), ()>::OUT,
                );
                self.assign_row(
                    &mut table,
                    15,
                    Cmpae::<(), ()>::OP_CODE,
                    Cmpae::<(), ()>::OUT,
                );
                self.assign_row(
                    &mut table,
                    16,
                    Cmpg::<(), ()>::OP_CODE,
                    Cmpg::<(), ()>::OUT,
                );
                self.assign_row(
                    &mut table,
                    17,
                    Cmpge::<(), ()>::OP_CODE,
                    Cmpge::<(), ()>::OUT,
                );
                self.assign_row(
                    &mut table,
                    18,
                    Mov::<(), ()>::OP_CODE,
                    Mov::<(), ()>::OUT,
                );
                self.assign_row(
                    &mut table,
                    19,
                    CMov::<(), ()>::OP_CODE,
                    CMov::<(), ()>::OUT,
                );
                self.assign_row(&mut table, 20, Jmp::<()>::OP_CODE, Jmp::<()>::OUT);
                self.assign_row(
                    &mut table,
                    21,
                    CJmp::<()>::OP_CODE,
                    CJmp::<()>::OUT,
                );
                self.assign_row(
                    &mut table,
                    22,
                    CnJmp::<()>::OP_CODE,
                    CnJmp::<()>::OUT,
                );
                self.assign_row(
                    &mut table,
                    23,
                    StoreW::<(), ()>::OP_CODE,
                    StoreW::<(), ()>::OUT,
                );
                self.assign_row(
                    &mut table,
                    24,
                    LoadW::<(), ()>::OP_CODE,
                    LoadW::<(), ()>::OUT,
                );
                self.assign_row(
                    &mut table,
                    25,
                    Answer::<()>::OP_CODE,
                    Answer::<()>::OUT,
                );
                Ok(())
            },
        )
    }
}
