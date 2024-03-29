use halo2_proofs::{
    pasta::Fp,
    plonk::{BatchVerifier, Circuit},
};

pub fn gen_proofs_and_verify<
    const WORD_BITS: u32,
    C: Circuit<Fp> + Default + Clone,
>(
    inputs: Vec<(C, Vec<Vec<Fp>>)>,
) {
    use halo2_proofs::pasta::{vesta, EqAffine};
    use halo2_proofs::{
        plonk::{create_proof, keygen_pk, keygen_vk, verify_proof, SingleVerifier},
        poly::commitment::Params,
        transcript::{Blake2bRead, Blake2bWrite},
    };
    use rand_core::OsRng;

    let k = 2 + WORD_BITS / 2;
    let params: Params<EqAffine> = halo2_proofs::poly::commitment::Params::new(k);
    let empty_circuit = C::default();
    let vk = keygen_vk(&params, &empty_circuit).unwrap();

    let pk = keygen_pk(&params, vk.clone(), &empty_circuit).unwrap();

    let inputs_ref: Vec<(C, Vec<&[Fp]>)> = inputs
        .iter()
        .map(|(circuit, public_input)| {
            (
                circuit.clone(),
                public_input.iter().map(|v| v.as_slice()).collect(),
            )
        })
        .collect();

    let proofs: Vec<(Vec<u8>, &[&[Fp]])> = inputs_ref
        .iter()
        .map(|(circuit, c)| {
            let mut transcript = Blake2bWrite::<_, vesta::Affine, _>::init(vec![]);
            create_proof(
                &params,
                &pk,
                &[circuit.clone()],
                &[c.as_slice()],
                &mut OsRng,
                &mut transcript,
            )
            .expect("Failed to create proof");

            let proof: Vec<u8> = transcript.finalize();
            (proof, c.as_slice())
        })
        .collect();

    let mut verifier = BatchVerifier::new();
    for ((proof, _), (_, c)) in proofs.iter().zip(inputs.iter()) {
        verifier.add_proof(vec![c.clone()], proof.clone());
    }

    let verified = verifier.finalize(&params, &vk);
    if !verified {
        for (proof, c) in proofs {
            let verifier = SingleVerifier::new(&params);
            let mut transcript = Blake2bRead::init(&proof[..]);

            verify_proof(&params, pk.get_vk(), verifier, &[c], &mut transcript)
                .expect("could not verify_proof");
        }
    }
}

pub fn gen_proofs_and_verify_should_fail<
    const WORD_BITS: u32,
    C: Circuit<Fp> + Default + Clone,
>(
    circuit: C,
    public_input: Vec<Fp>,
) {
    use halo2_proofs::pasta::{vesta, EqAffine};
    use halo2_proofs::{
        plonk::{create_proof, keygen_pk, keygen_vk, verify_proof, SingleVerifier},
        poly::commitment::Params,
        transcript::{Blake2bRead, Blake2bWrite},
    };
    use rand_core::OsRng;

    let k = 1 + WORD_BITS / 2;
    let params: Params<EqAffine> = halo2_proofs::poly::commitment::Params::new(k);
    let empty_circuit = C::default();
    let vk = keygen_vk(&params, &empty_circuit).unwrap();

    let pk = keygen_pk(&params, vk, &empty_circuit).unwrap();

    let mut transcript = Blake2bWrite::<_, vesta::Affine, _>::init(vec![]);
    create_proof(
        &params,
        &pk,
        &[circuit],
        &[&[&public_input]],
        &mut OsRng,
        &mut transcript,
    )
    .expect("Failed to create proof");

    let proof: Vec<u8> = transcript.finalize();

    let verifier = SingleVerifier::new(&params);
    let mut transcript = Blake2bRead::init(&proof[..]);

    verify_proof(
        &params,
        pk.get_vk(),
        verifier,
        &[&[&public_input]],
        &mut transcript,
    )
    .expect_err("Erroneously verified proof");
}
