use std::marker::PhantomData;

use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Chip, Layouter, SimpleFloorPlanner},
    plonk::{Circuit, Column, ConstraintSystem, Error, Instance},
};

use crate::{
    assign::{NewColumn, PseudoMeta, PushRow},
    trace,
};

use super::aux::{TempVarSelectors, TempVarSelectorsRow};

pub struct ProgChip<F: FieldExt, const WORD_BITS: u32, const REG_COUNT: usize> {
    config: ProgConfig<WORD_BITS, REG_COUNT, Column<Instance>>,
    _marker: PhantomData<F>,
}

#[derive(Debug, Clone)]
pub struct ProgConfig<
    const WORD_BITS: u32,
    const REG_COUNT: usize,
    C: Copy = Column<Instance>,
> {
    pc: C,
    opcode: C,
    /// Field #2 is 0 if A is a register name and 1 if A is an immediate value (TinyRam 2 spec).
    /// Denotes the type of `immediate`.
    a_type: C,
    ri: C,
    rj: C,
    immediate: C,

    s: C,
    l: C,

    temp_vars: TempVarSelectors<REG_COUNT, C>,
}

impl<F: FieldExt, const WORD_BITS: u32, const REG_COUNT: usize> Chip<F>
    for ProgChip<F, WORD_BITS, REG_COUNT>
{
    type Config = ProgConfig<WORD_BITS, REG_COUNT>;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

impl<F: FieldExt, const WORD_BITS: u32, const REG_COUNT: usize>
    ProgChip<F, WORD_BITS, REG_COUNT>
{
    fn construct(config: ProgConfig<WORD_BITS, REG_COUNT>) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }

    fn configure(
        meta: &mut ConstraintSystem<F>,
    ) -> ProgConfig<WORD_BITS, REG_COUNT> {
        let config = Self::new_columns(meta);

        // meta.create_gate("single selector bit set", |meta| {
        //     // let TempVarSelectors { a, b, c, d, .. }
        //     // meta.q
        // });

        config
    }

    // This could be a method on `ProgConfig`,
    // but that would require specifying types when calling this method.
    fn new_columns<C: Copy, M>(meta: &mut M) -> ProgConfig<WORD_BITS, REG_COUNT, C>
    where
        M: NewColumn<C>,
    {
        let pc = meta.new_column();

        let opcode = meta.new_column();
        let a_type = meta.new_column();
        let ri = meta.new_column();
        let rj = meta.new_column();
        let immediate = meta.new_column();

        let s = meta.new_column();
        let l = meta.new_column();

        let temp_vars = TempVarSelectors::new::<F, M>(meta);
        ProgConfig {
            pc,
            opcode,
            a_type,
            ri,
            rj,
            immediate,
            s,
            l,
            temp_vars,
        }
    }

    pub fn program(program: &trace::Program) -> Vec<Vec<F>> {
        let mut meta = PseudoMeta::<F>::default();
        let ProgConfig {
            pc,
            opcode,
            a_type,
            ri,
            rj,
            immediate,
            s,
            l,
            temp_vars,
        } = Self::new_columns(&mut meta);

        for (pc_v, inst) in program.0.iter().enumerate() {
            meta.push_cell(pc, F::from_u128(pc_v as u128)).unwrap();
            meta.push_cell(opcode, F::from_u128(inst.opcode())).unwrap();
            meta.push_cell(a_type, F::from(inst.a().immediate().is_some()))
                .unwrap();
            meta.push_cell(
                ri,
                F::from_u128(inst.ri().map(|ri| ri.0).unwrap_or_default() as _),
            )
            .unwrap();
            meta.push_cell(
                rj,
                F::from_u128(inst.rj().map(|rj| rj.0).unwrap_or_default() as _),
            )
            .unwrap();
            meta.push_cell(
                immediate,
                F::from_u128(inst.a().immediate().unwrap_or_default().into()),
            )
            .unwrap();
            meta.push_cell(s, inst.is_store().into()).unwrap();
            meta.push_cell(l, inst.is_load().into()).unwrap();
            temp_vars.push_cells(&mut meta, TempVarSelectorsRow::from(inst))
        }
        meta.0
    }
}

#[test]
fn fp_from_bool() {
    // We rely on this property
    assert_eq!(halo2_proofs::pasta::Fp::zero(), false.into());
    assert_eq!(halo2_proofs::pasta::Fp::one(), true.into());
}

#[derive(Default)]
pub struct ProgCircuit<const WORD_BITS: u32, const REG_COUNT: usize> {
    pub prog: Option<trace::Program>,
}

impl<F: FieldExt, const WORD_BITS: u32, const REG_COUNT: usize> Circuit<F>
    for ProgCircuit<WORD_BITS, REG_COUNT>
{
    type Config = ProgConfig<WORD_BITS, REG_COUNT, Column<Instance>>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        // We create the two advice columns that AndChip uses for I/O.
        let advice = [meta.advice_column(), meta.advice_column()];

        ProgChip::<F, WORD_BITS, REG_COUNT>::new_columns::<Column<Instance>, _>(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        // let even_bits_chip = EvenBitsChip::<F, WORD_BITS>::construct(config.1);
        // even_bits_chip.alloc_table(&mut layouter.namespace(|| "alloc table"))?;
        // let prog_chip = ProgChip::<F, WORD_BITS, REG_COUNT>::construct(config.0);

        // let prog = self
        //     .prog
        //     .as_ref()
        //     .expect("A trace must be set before synthesis");
        // TODO verify store load
        // TODO constrain selectors
        // TODO constrain words
        // TODO constrain last address to answer zero

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use halo2_proofs::dev::MockProver;
    use halo2_proofs::pasta::Fp;

    use crate::{
        circuits::tables::prog::{ProgChip, ProgCircuit},
        trace::*,
    };

    fn load_and_answer<const WORD_BITS: u32, const REG_COUNT: usize>(
    ) -> Trace<WORD_BITS, REG_COUNT> {
        let prog = Program(vec![
            Instruction::LoadW(LoadW {
                ri: RegName(0),
                a: ImmediateOrRegName::Immediate(Word(0)),
            }),
            Instruction::And(And {
                ri: RegName(1),
                rj: RegName(0),
                a: ImmediateOrRegName::Immediate(Word(0b1)),
            }),
            Instruction::Answer(Answer {
                a: ImmediateOrRegName::RegName(RegName(1)),
            }),
        ]);

        let trace = prog.eval::<WORD_BITS, REG_COUNT>(Mem::new(&[Word(0b1)], &[]));
        assert_eq!(trace.ans.0, 0b1);
        trace
    }

    #[test]
    fn circuit_layout_test() {
        const WORD_BITS: u32 = 8;
        const REG_COUNT: usize = 8;
        let prog = Some(load_and_answer::<WORD_BITS, REG_COUNT>().prog);

        let k = 1 + WORD_BITS / 2;

        // Instantiate the circuit with the private inputs.
        let circuit = ProgCircuit::<WORD_BITS, REG_COUNT> { prog };
        use plotters::prelude::*;
        let root =
            BitMapBackend::new("layout.png", (1080, 1920)).into_drawing_area();
        root.fill(&WHITE).unwrap();
        let root = root
            .titled("Prog Circuit Layout", ("sans-serif", 60))
            .unwrap();

        halo2_proofs::dev::CircuitLayout::default()
            .mark_equality_cells(true)
            .show_equality_constraints(true)
            // The first argument is the size parameter for the circuit.
            .render::<Fp, _, _>(k, &circuit, &root)
            .unwrap();

        let dot_string = halo2_proofs::dev::circuit_dot_graph::<Fp, _>(&circuit);
        let mut dot_graph = std::fs::File::create("circuit.dot").unwrap();
        std::io::Write::write_all(&mut dot_graph, dot_string.as_bytes()).unwrap();
    }

    fn mock_prover_test<const WORD_BITS: u32, const REG_COUNT: usize>(
        trace: Trace<WORD_BITS, REG_COUNT>,
    ) {
        let k = 1 + WORD_BITS / 2;

        let public = ProgChip::<Fp, WORD_BITS, REG_COUNT>::program(&trace.prog);

        let circuit = ProgCircuit::<WORD_BITS, REG_COUNT> {
            prog: Some(trace.prog),
        };
        // Given the correct public input, our circuit will verify.
        let prover = MockProver::<Fp>::run(k, &circuit, public).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn load_and_answer_mock_prover() {
        mock_prover_test::<8, 8>(load_and_answer())
    }

    #[test]
    fn answer_mock_prover() {
        let prog = Program(vec![Instruction::Answer(Answer {
            a: ImmediateOrRegName::Immediate(Word(1)),
        })]);

        let trace = prog.eval::<8, 8>(Mem::new(&[], &[]));
        assert_eq!(trace.ans.0, 1);

        mock_prover_test::<8, 8>(trace)
    }
}
