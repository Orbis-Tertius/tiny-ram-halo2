use halo2_proofs::dev::MockProver;
use pasta_curves::Fp;
use tiny_ram_halo2::gadgets::{and::AndCircuit, cmpa::GreaterThanCircuit};

fn main() {
    const WORD_BITS: u32 = 8;
    // ANCHOR: test-circuit
    // The number of rows in our circuit cannot exceed 2^k. Since our example
    // circuit is very small, we can pick a very small value here.
    let k = 5;

    // Prepare the private and public inputs to the circuit!
    const A: u64 = 3;
    const B: u64 = 4;
    let a = Fp::from(A);
    let b = Fp::from(B);
    let c = Fp::from(A & B);

    // Instantiate the circuit with the private inputs.
    let circuit = AndCircuit::<Fp, WORD_BITS> {
        a: Some(a),
        b: Some(b),
    };

    // Arrange the public input. We expose the bitwise AND result in row 0
    // of the instance column, so we position it there in our public inputs.
    let public_inputs = vec![c];

    // Given the correct public input, our circuit will verify.
    let prover = MockProver::run(k, &circuit, vec![public_inputs]).unwrap();
    assert_eq!(prover.verify(), Ok(()));

    let a = Fp::from(4);
    let b = Fp::from(3);

    let circuit = GreaterThanCircuit::<Fp, WORD_BITS> {
        a: Some(a),
        b: Some(b),
    };

    let public_inputs = vec![Fp::one()];

    let prover = MockProver::run(k, &circuit, vec![public_inputs]).unwrap();
    assert_eq!(prover.verify(), Ok(()));
}
