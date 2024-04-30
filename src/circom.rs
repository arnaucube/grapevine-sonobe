#[cfg(test)]
mod test {
    use super::*;
    use crate::params::test_nova_setup;
    use crate::utils::inputs::{
        get_z0, prepare_external_inputs, random_f_bigint, CircomPrivateInput,
    };
    use ark_bn254::{constraints::GVar, Fr, G1Projective as Projective};
    // use ark_circom::circom::CircomCircuit;
    use ark_ff::{BigInteger, PrimeField};
    use ark_grumpkin::{constraints::GVar as GVar2, Projective as Projective2};
    use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar, R1CSVar};
    use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
    use lazy_static::lazy_static;
    use num_bigint::{BigInt, Sign};
    use sonobe::{
        commitment::pedersen::Pedersen, folding::nova::Nova, frontend::circom::CircomFCircuit,
        transcript::poseidon::poseidon_test_config, Error, FoldingScheme,
    };
    use sonobe::{frontend::FCircuit, Error as SonobeError};
    use std::env::current_dir;
    use std::path::PathBuf;
    use std::time::Instant;

    use crate::errors::GrapevineError;

    lazy_static! {
        pub static ref R1CS_PATH: PathBuf = PathBuf::from("./circom/artifacts/grapevine.r1cs");
        pub static ref WASM_PATH: PathBuf = PathBuf::from("./circom/artifacts/grapevine.wasm");
        pub static ref PHRASE: String = String::from("This is a secret");
        pub static ref USERNAMES: [String; 5] = [
            String::from("alice"),
            String::from("bob"),
            String::from("charlie"),
            String::from("david"),
            String::from("eve")
        ];
        pub static ref AUTH_SECRETS: [BigInt; 5] = (0..5)
            .map(|_| random_f_bigint::<Fr>())
            .collect::<Vec<BigInt>>()
            .try_into()
            .unwrap();
    }

    // Converts a PrimeField element to a num_bigint::BigInt representation.
    pub fn ark_primefield_to_num_bigint<F: PrimeField>(value: F) -> BigInt {
        let primefield_bigint: F::BigInt = value.into_bigint();
        let bytes = primefield_bigint.to_bytes_be();
        BigInt::from_bytes_be(Sign::Plus, &bytes)
    }

    /// This test tests the circom circuit without using anything from Sonobe, just using
    /// arkworks/circom-compat to check the Grapevine circuit.
    #[test]
    fn test_circom_circuit() {
        // define inputs
        let step_0_inputs = CircomPrivateInput {
            phrase: Some(String::from(&*PHRASE)),
            usernames: [None, Some(String::from(&*USERNAMES[0]))],
            auth_secrets: [None, Some(AUTH_SECRETS[0].clone())],
            chaff: false,
        };
        let external_inputs = prepare_external_inputs::<Fr>(&step_0_inputs);
        let z_0 = get_z0::<Fr>();
        dbg!(&z_0);

        let z_0_bi = z_0
            .iter()
            .map(|val| ark_primefield_to_num_bigint(*val))
            .collect::<Vec<BigInt>>();
        let external_inputs_bi = external_inputs
            .iter()
            .map(|val| ark_primefield_to_num_bigint(*val))
            .collect::<Vec<BigInt>>();

        use ark_circom::{CircomBuilder, CircomConfig};
        let cfg = CircomConfig::<Fr>::new(
            "./circom/artifacts/grapevine.wasm",
            "./circom/artifacts/grapevine.r1cs",
        )
        .unwrap();

        let mut builder = CircomBuilder::new(cfg);

        // Insert our public inputs as key value pairs
        use std::collections::HashMap;
        builder.inputs = HashMap::from([
            ("ivc_input".to_string(), z_0_bi),
            ("external_ipnuts".to_string(), external_inputs_bi),
        ]);
        dbg!(&builder.inputs);

        let circom = builder.build().unwrap();

        // extract the public output (ivc_output) from the computed witness and print it
        let z_1 = circom.witness.unwrap()[1..1 + 6 + 4].to_vec();
        println!("z_1: {:?}", z_1);
    }

    #[test]
    fn test_step_native() {
        // define inputs
        let step_0_inputs = CircomPrivateInput {
            phrase: Some(String::from(&*PHRASE)),
            usernames: [None, Some(String::from(&*USERNAMES[0]))],
            auth_secrets: [None, Some(AUTH_SECRETS[0].clone())],
            chaff: false,
        };
        let external_inputs = prepare_external_inputs::<Fr>(&step_0_inputs);

        // initialize new Grapevine function circuit
        let f_circuit =
            CircomFCircuit::<Fr>::new((R1CS_PATH.clone(), WASM_PATH.clone(), 4, 6 + 4)).unwrap(); // 4=ivc_input.lenght, 6+4=external_inputs

        let z_0 = get_z0();
        let z_1 = f_circuit
            .step_native(0, z_0.to_vec(), external_inputs)
            .unwrap();
        println!("z_1: {:?}", z_1);
    }

    #[test]
    fn test_step_constraints() {
        // define inputs
        let step_0_inputs = CircomPrivateInput {
            phrase: Some(String::from(&*PHRASE)),
            usernames: [None, Some(String::from(&*USERNAMES[0]))],
            auth_secrets: [None, Some(AUTH_SECRETS[0].clone())],
            chaff: false,
        };
        let external_inputs = prepare_external_inputs::<Fr>(&step_0_inputs);

        // initialize new Grapevine function circuit
        let f_circuit =
            CircomFCircuit::<Fr>::new((R1CS_PATH.clone(), WASM_PATH.clone(), 4, 6 + 4)).unwrap(); // 4=ivc_input.lenght, 6+4=external_inputs

        let z_0 = get_z0();
        let z_1 = f_circuit
            .step_native(0, z_0.to_vec(), external_inputs.clone())
            .unwrap();

        // assign z0
        let cs = ConstraintSystem::<Fr>::new_ref();
        let z_0_var = Vec::<FpVar<Fr>>::new_witness(cs.clone(), || Ok(z_0)).unwrap();
        let external_inputs_var =
            Vec::<FpVar<Fr>>::new_witness(cs.clone(), || Ok(external_inputs)).unwrap();

        // compute constraints for step 0
        let z_1_var = f_circuit
            .generate_step_constraints(cs.clone(), 1, z_0_var, external_inputs_var)
            .unwrap();
        println!("z_1: {:?}", z_1_var);

        assert_eq!(z_1_var.value().unwrap(), z_1);
    }

    // WIP
    /*
    #[test]
    fn test_multiple_steps_native() {
        // initialize new Grapevine function circuit
        let mut f_circuit = GrapevineFCircuit::<Fr>::new((R1CS_PATH.clone(), WASM_PATH.clone()));

        /*  DEGREE 1  */
        // define degree 1 logic inputs
        let inputs = CircomPrivateInput {
            phrase: Some(String::from(&*PHRASE)),
            usernames: [None, Some(String::from(&*USERNAMES[0]))],
            auth_secrets: [None, Some(AUTH_SECRETS[0].clone())],
            chaff: false,
        };
        f_circuit.set_private_input(inputs);

        // compute step 0 (degree 1 logic step)
        let z_i = f_circuit.step_native(0, get_z0().to_vec()).unwrap();

        // define degree 1 chaff inputs
        let inputs = CircomPrivateInput::empty(true);
        f_circuit.set_private_input(inputs);

        // compute step 1 (degree 1 chaff step)
        let z_i = f_circuit.step_native(1, z_i.to_vec()).unwrap();
        println!("z_i: {:?}", z_i);

        /*  DEGREE 2  */
        // define degree 2 logic inputs
        let inputs = CircomPrivateInput {
            phrase: None,
            usernames: [
                Some(String::from(&*USERNAMES[0])),
                Some(String::from(&*USERNAMES[1])),
            ],
            auth_secrets: [Some(AUTH_SECRETS[0].clone()), Some(AUTH_SECRETS[1].clone())],
            chaff: false,
        };
        f_circuit.set_private_input(inputs);

        // compute step 2 (degree 2 logic step)
        let z_i = f_circuit.step_native(2, z_i.to_vec()).unwrap();

        // define degree 2 chaff inputs
        let inputs = CircomPrivateInput::empty(true);
        f_circuit.set_private_input(inputs);

        // compute step 3 (degree 2 chaff step)
        let z_i = f_circuit.step_native(3, z_i.to_vec()).unwrap();

        /*  DEGREE 3  */
        // define degree 3 logic inputs
        let inputs = CircomPrivateInput {
            phrase: None,
            usernames: [
                Some(String::from(&*USERNAMES[1])),
                Some(String::from(&*USERNAMES[2])),
            ],
            auth_secrets: [Some(AUTH_SECRETS[1].clone()), Some(AUTH_SECRETS[2].clone())],
            chaff: false,
        };
        f_circuit.set_private_input(inputs);

        // compute step 4 (degree 3 logic step)
        let z_i = f_circuit.step_native(4, z_i.to_vec()).unwrap();

        // define degree 3 chaff inputs
        let inputs = CircomPrivateInput::empty(true);
        f_circuit.set_private_input(inputs);

        // compute step 5 (degree 3 chaff step)
        let z_i = f_circuit.step_native(5, z_i.to_vec()).unwrap();

        /* RESULT */
        // @todo: compute hashes natively
        assert_eq!(z_i[0], Fr::from(3));
        assert_eq!(z_i[3], Fr::from(0));
    }
    */

    // #[test]
    // fn test_multiple_steps_constraints() {
    //     // initialize new Grapevine function circuit
    //     let mut f_circuit = GrapevineFCircuit::<Fr>::new((R1CS_PATH.clone(), WASM_PATH.clone()));
    //
    //     /*  DEGREE 1  */
    //     // define degree 1 logic inputs
    //     let inputs = CircomPrivateInput {
    //         phrase: Some(String::from(&*PHRASE)),
    //         usernames: [None, Some(String::from(&*USERNAMES[0]))],
    //         auth_secrets: [None, Some(AUTH_SECRETS[0].clone())],
    //         chaff: false
    //     };
    //     f_circuit.set_private_input(inputs);
    //
    //     // assign z0
    //     let cs = ConstraintSystem::<Fr>::new_ref();
    //     let z_0_var = Vec::<FpVar<Fr>>::new_witness(cs.clone(), || Ok(get_z0())).unwrap();
    //
    //     // compute constraints for step 0 (degree 1 logic step)
    //     let cs = ConstraintSystem::<Fr>::new_ref();
    //     let z_1_var = f_circuit
    //         .generate_step_constraints(cs.clone(), 0, z_0_var)
    //         .unwrap();
    //     println!("z_1: {:?}", z_1_var);
    //
    //     // define degree 1 chaff inputs
    //     let inputs = CircomPrivateInput::empty(true);
    //     f_circuit.set_private_input(inputs);
    //
    //     // compute step 1 (degree 1 chaff step)
    //     let z_i = f_circuit.step_native(1, z_i.to_vec()).unwrap();
    //     println!("z_i: {:?}", z_i);
    //
    //     // define inputs
    //     let step_0_inputs = CircomPrivateInput {
    //         phrase: Some(String::from(&*PHRASE)),
    //         usernames: [None, Some(String::from(&*USERNAMES[0]))],
    //         auth_secrets: [None, Some(AUTH_SECRETS[0].clone())],
    //         chaff: false
    //     };
    //
    //     // initialize new Grapevine function circuit
    //     let mut f_circuit = GrapevineFCircuit::<Fr>::new((R1CS_PATH.clone(), WASM_PATH.clone()));
    //     f_circuit.set_private_input(step_0_inputs);
    //
    // }

    /*
    #[test]
    fn test_full_one_step() {
        // initialize new Grapevine function circuit
        let mut f_circuit = GrapevineFCircuit::<Fr>::new((R1CS_PATH.clone(), WASM_PATH.clone()));

        // Get test params
        let (prover_params, verifier_params) =
            test_nova_setup::<GrapevineFCircuit<Fr>>(f_circuit.clone());

        // define inputs
        // define inputs
        let step_0_inputs = CircomPrivateInput {
            phrase: Some(String::from(&*PHRASE)),
            usernames: [None, Some(String::from(&*USERNAMES[0]))],
            auth_secrets: [None, Some(AUTH_SECRETS[0].clone())],
            chaff: false,
        };
        // let z_0 = get_z0();
    }

    #[test]
    fn test_full() {
        let num_steps = 10;
        let initial_state = vec![Fr::from(19), Fr::from(0)];

        let r1cs_path = PathBuf::from("./circom/artifacts/grapevine.r1cs");
        let wasm_path = PathBuf::from("./circom/artifacts/grapevine.wasm");

        let f_circuit = GrapevineFCircuit::<Fr>::new((r1cs_path, wasm_path));

        let start = Instant::now();
        println!("Generating params...");
        let (prover_params, verifier_params) =
            test_nova_setup::<GrapevineFCircuit<Fr>>(f_circuit.clone());
        println!("Generated params: {:?}", start.elapsed());
        type NOVA = Nova<
            Projective,
            GVar,
            Projective2,
            GVar2,
            GrapevineFCircuit<Fr>,
            Pedersen<Projective>,
            Pedersen<Projective2>,
        >;

        let start = Instant::now();
        println!("Initializing folding scheme...");
        let mut folding_scheme =
            NOVA::init(&prover_params, f_circuit, initial_state.clone()).unwrap();
        println!("Initialized folding scheme: {:?}", start.elapsed());

        for i in 0..num_steps {
            let start = Instant::now();
            folding_scheme.prove_step().unwrap();
            println!("Proved step {}: {:?}", i, start.elapsed());
        }

        let (running_instance, incoming_instance, cyclefold_instance) = folding_scheme.instances();

        println!("Running IVC Verifier...");
        let start = Instant::now();
        NOVA::verify(
            verifier_params,
            initial_state.clone(),
            folding_scheme.state(),
            Fr::from(num_steps as u32),
            running_instance,
            incoming_instance,
            cyclefold_instance,
        )
        .unwrap();
        println!("Verified: {:?}", start.elapsed());
    }
    */
}
