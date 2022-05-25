use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{AssignedCell, Region},
    plonk::{Advice, Column, ConstraintSystem, Fixed, Instance},
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

pub trait PushRow<F, C> {
    type AssignedRef;
    fn push_cell(
        &mut self,
        column: C,
        f: F,
    ) -> Result<Self::AssignedRef, halo2_proofs::plonk::Error>;
}

/// An impl of push_cell for `(Region, offset)`.
impl<'r, F: FieldExt>
    PushRow<F, halo2_proofs::plonk::Column<halo2_proofs::plonk::Advice>>
    for (&mut Region<'r, F>, usize)
{
    type AssignedRef = AssignedCell<F, F>;
    fn push_cell(
        &mut self,
        column: Column<Advice>,
        f: F,
    ) -> Result<Self::AssignedRef, halo2_proofs::plonk::Error> {
        self.0.assign_advice(|| "", column, self.1, &mut || Ok(f))
    }
}

impl<'r, F> PushRow<F, PseudoColumn> for PseudoMeta<F> {
    type AssignedRef = (PseudoColumn, usize);
    fn push_cell(
        &mut self,
        column: PseudoColumn,
        f: F,
    ) -> Result<Self::AssignedRef, halo2_proofs::plonk::Error> {
        self.0[column.0].push(f);
        Ok((column, self.0[column.0].len() - 1))
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
