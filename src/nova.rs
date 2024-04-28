use ark_bn254::{constraints::GVar, Fr, G1Projective as Projective};
use ark_crypto_primitives::{
    crh::{
        poseidon::constraints::{CRHGadget, CRHParametersVar},
        poseidon::CRH,
        CRHScheme, CRHSchemeGadget,
    },
    sponge::{poseidon::PoseidonConfig, Absorb},
};
use ark_ff::PrimeField;
use ark_grumpkin::{constraints::GVar as Gvar2, Projective as Projective2};
use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar, fields::FieldVar};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use ark_std::Zero;
use core::marker::PhantomData;
use sonobe::{
    commitment::{pedersen::Pedersen, CommitmentScheme},
    folding::nova::{get_r1cs, ProverParams, VerifierParams},
    frontend::{circom::CircomFCircuit, FCircuit},
    transcript::poseidon::poseidon_test_config,
};
use std::time::Instant;

use crate::params::test_nova_setup;

/* WIP
#[cfg(test)]
mod test {
    use super::*;
    use std::path::PathBuf;
    use std::time::Instant;
    #[test]
    fn test_generate_params() {
        let r1cs_path = PathBuf::from("./circom/artifacts/circuit.r1cs");
        let wasm_path = PathBuf::from("./circom/artifacts/circuit.wasm");
        let f_circuit = CircomFCircuit::<Fr>::new((r1cs_path, wasm_path, 4, 6 + 4)); // 4=ivc_input.lenght, 6+4=external_inputs

        let pre = Instant::now();
        let (prover_params, verifier_params) = test_nova_setup::<GrapevineFCircuit<Fr>>(f_circuit);
        // let prover_params_str = serde_json::to_string(&prover_params).unwrap();
        // let verifier_params_str = serde_json::to_string(&verifier_params).unwrap();

        println!("Time to generate params: {:?}", pre.elapsed());
    }
}
*/
