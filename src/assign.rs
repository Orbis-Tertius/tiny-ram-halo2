use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{AssignedCell, Region, Table, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Fixed, Instance, TableColumn},
};

pub trait NewColumn<C: Copy> {
    fn new_column(&mut self) -> C;
}

impl<F: FieldExt> NewColumn<Column<Advice>> for ConstraintSystem<F> {
    fn new_column(&mut self) -> Column<Advice> {
        self.advice_column()
    }
}

impl<F: FieldExt> NewColumn<Column<Instance>> for ConstraintSystem<F> {
    fn new_column(&mut self) -> Column<Instance> {
        self.instance_column()
    }
}

impl<F: FieldExt> NewColumn<Column<Fixed>> for ConstraintSystem<F> {
    fn new_column(&mut self) -> Column<Fixed> {
        self.fixed_column()
    }
}

pub struct TrackColumns<'l, F: FieldExt, C: Copy>(
    pub &'l mut ConstraintSystem<F>,
    pub Vec<C>,
);

impl<'l, F: FieldExt, C: Copy> TrackColumns<'l, F, C> {
    pub fn new(meta: &'l mut ConstraintSystem<F>) -> Self {
        TrackColumns(meta, Vec::new())
    }
}

impl<'l, F: FieldExt, C: Copy> NewColumn<C> for TrackColumns<'l, F, C>
where
    ConstraintSystem<F>: NewColumn<C>,
{
    fn new_column(&mut self) -> C {
        let c = self.0.new_column();
        self.1.push(c);
        c
    }
}

pub trait ConstraintSys<F: FieldExt, C: Copy>: NewColumn<C> {
    fn cs(&mut self) -> &mut ConstraintSystem<F>;
}

impl<F: FieldExt, C: Copy> ConstraintSys<F, C> for ConstraintSystem<F>
where
    ConstraintSystem<F>: NewColumn<C>,
{
    fn cs(&mut self) -> &mut ConstraintSystem<F> {
        self
    }
}

impl<'l, F: FieldExt, C: Copy> ConstraintSys<F, C> for TrackColumns<'l, F, C>
where
    ConstraintSystem<F>: NewColumn<C>,
{
    fn cs(&mut self) -> &mut ConstraintSystem<F> {
        self.0
    }
}

pub trait AssignCell<F, C> {
    type AssignedRef;
    fn assign_cell(
        &mut self,
        column: C,
        offset: usize,
        f: F,
    ) -> Result<Self::AssignedRef, Error>;
}

/// An impl of push_cell for `(Region, offset)`.
impl<'r, F: FieldExt> AssignCell<F, Column<Advice>> for Region<'r, F> {
    type AssignedRef = AssignedCell<F, F>;
    fn assign_cell(
        &mut self,
        column: Column<Advice>,
        offset: usize,
        f: F,
    ) -> Result<Self::AssignedRef, Error> {
        self.assign_advice(|| "", column, offset, &mut || Value::known(f))
    }
}

/// An impl of push_cell for `(Region, offset)`.
impl<'r, F: FieldExt> AssignCell<F, TableColumn> for Table<'r, F> {
    type AssignedRef = ();
    fn assign_cell(
        &mut self,
        column: TableColumn,
        offset: usize,
        f: F,
    ) -> Result<Self::AssignedRef, Error> {
        self.assign_cell(|| "", column, offset, &mut || Value::known(f))
    }
}

impl<F> AssignCell<F, PseudoColumn> for PseudoMeta<F> {
    type AssignedRef = (PseudoColumn, usize);
    fn assign_cell(
        &mut self,
        column: PseudoColumn,
        offset: usize,
        f: F,
    ) -> Result<Self::AssignedRef, Error> {
        // We only support assigning rows in order.
        assert_eq!(
            self.0.get(column.0).expect("Column Not Allocated").len(),
            offset
        );
        self.0[column.0].push(f);
        Ok((column, offset))
    }
}

#[derive(Debug, Clone, Default)]
pub struct PseudoMeta<F>(pub Vec<Vec<F>>);

#[derive(Debug, Clone, Copy)]
pub struct PseudoColumn(pub usize);

impl<F> NewColumn<PseudoColumn> for PseudoMeta<F> {
    fn new_column(&mut self) -> PseudoColumn {
        self.0.push(Vec::new());
        PseudoColumn(self.0.len() - 1)
    }
}
