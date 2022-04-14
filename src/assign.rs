use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{AssignedCell, Region},
    plonk::{Advice, Column, ColumnType, ConstraintSystem, Fixed, Instance},
};

pub trait NewColumn<C: ColumnType> {
    fn new_column(&mut self) -> Column<C>;
}

impl<F: FieldExt> NewColumn<Advice> for ConstraintSystem<F> {
    fn new_column(&mut self) -> Column<Advice> {
        self.advice_column()
    }
}

impl<F: FieldExt> NewColumn<Instance> for ConstraintSystem<F> {
    fn new_column(&mut self) -> Column<Instance> {
        self.instance_column()
    }
}

impl<F: FieldExt> NewColumn<Fixed> for ConstraintSystem<F> {
    fn new_column(&mut self) -> Column<Fixed> {
        self.fixed_column()
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

impl<'r, F: FieldExt>
    PushRow<F, halo2_proofs::plonk::Column<halo2_proofs::plonk::Advice>>
    for Region<'r, F>
{
    type AssignedRef = AssignedCell<F, F>;
    fn push_cell(
        &mut self,
        column: Column<Advice>,
        f: F,
    ) -> Result<Self::AssignedRef, halo2_proofs::plonk::Error> {
        self.assign_advice(|| "", column, 0, &mut || Ok(f))
    }
}

impl<'r, F> PushRow<F, Instance> for Vec<F> {
    type AssignedRef = usize;
    fn push_cell(
        &mut self,
        _column: Instance,
        f: F,
    ) -> Result<Self::AssignedRef, halo2_proofs::plonk::Error> {
        self.push(f);
        Ok(self.len() - 1)
    }
}
