use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Region, Value},
    plonk::{
        Advice, Column, ConstraintSystem, Error, Expression, Selector, VirtualCells,
    },
    poly::Rotation,
};

pub mod aux;
pub mod even_bits;
pub mod exe;
pub mod mem;
pub mod pow;
pub mod prog;
pub mod signed;

#[derive(Debug, Clone, Copy)]
pub struct TableSelector {
    /// A Selector denoting the extent of dynamic table.
    /// Enabled for every row that may contain a line of the trace.
    /// The trace may be the Exe trace or the memory access trace.
    pub s_table: Selector,
    /// An advice selector denoting the extent of the trace.
    /// Enabled for every row that contains a line of the trace.
    pub s_trace: Column<Advice>,
}

impl TableSelector {
    pub fn configure<F: FieldExt>(meta: &mut ConstraintSystem<F>) -> Self {
        let s_table = meta.complex_selector();
        let s_trace = meta.advice_column();
        Self { s_table, s_trace }
    }

    pub fn query<F: FieldExt>(
        self: TableSelector,
        meta: &mut VirtualCells<F>,
    ) -> Expression<F> {
        let s_table = meta.query_selector(self.s_table);
        let s_trace = meta.query_advice(self.s_trace, Rotation::cur());
        Expression::SelectorExpression(Box::new(s_table * s_trace))
    }

    /// Query the current row of `s_table`, and the next row of s_trace.
    /// Useful for constraints that should not be applied on the last line of the trace.
    pub fn query_trace_next<F: FieldExt>(
        self: TableSelector,
        meta: &mut VirtualCells<F>,
    ) -> Expression<F> {
        let s_table = meta.query_selector(self.s_table);
        let s_trace = meta.query_advice(self.s_trace, Rotation::next());
        Expression::SelectorExpression(Box::new(s_table * s_trace))
    }

    pub fn alloc_table_rows<F: FieldExt>(
        &self,
        region: &mut Region<F>,
        table_len: usize,
    ) -> Result<(), Error> {
        for offset in 0..table_len {
            self.s_table.enable(region, offset)?;
        }
        Ok(())
    }

    /// Enable a row of an already allocated table.
    pub fn enable_row_of_table<F: FieldExt>(
        &self,
        region: &mut Region<F>,
        offset: usize,
        enable: bool,
    ) -> Result<(), Error> {
        region.assign_advice(
            || "s_trace",
            self.s_trace,
            offset,
            || Value::known(F::from(enable)),
        )?;

        // The table should already be allocated, but if it's not this line makes debugging easier.
        self.s_table.enable(region, offset)?;

        Ok(())
    }
}
