use std::marker::PhantomData;

use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::Chip,
    plonk::{Advice, Column, Fixed},
};

use super::aux::TempVarSelectors;

pub struct ExeChip<F: FieldExt, const REG_COUNT: usize> {
    config: ExeConfig<REG_COUNT>,
    _marker: PhantomData<F>,
}

pub struct ExeConfig<const REG_COUNT: usize> {
    // Not sure this is right.
    time: Column<Fixed>,
    pc: Column<Advice>,
    instruction: Column<Advice>,
    immediate: Column<Advice>,
    reg: [Column<Advice>; REG_COUNT],
    a: Column<Advice>,
    b: Column<Advice>,
    c: Column<Advice>,
    d: Column<Advice>,
    out: Column<Advice>,

    t_link: Column<Advice>,
    v_link: Column<Advice>,
    v_init: Column<Advice>,
    usd: Column<Advice>,
    s: Column<Advice>,
    l: Column<Advice>,

    temp_vars: TempVarSelectors<REG_COUNT>,
}

// impl<F: FieldExt, const REG_COUNT: usize> ExeChip<F, REG_COUNT> {
//     fn construct(config: ExeConfig<REG_COUNT>) -> Self {
//         Self {
//             config,
//             _marker: PhantomData,
//         }
//     }


//     fn configure(
//         meta: &mut ConstraintSystem<F>,
//         advice: [Column<Advice>; 2],
//         instance: Column<Instance>,
//         constant: Column<Fixed>,
//     ) -> <Self as Chip<F>>::Config {

//     }
// }
