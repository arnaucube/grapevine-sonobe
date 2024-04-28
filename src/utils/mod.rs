use ark_bn254::Fr;
use ark_ff::UniformRand;
use ark_std::rand::rngs::OsRng;

pub mod inputs;

pub const SECRET_FIELD_LENGTH: usize = 6;
pub const MAX_SECRET_LENGTH: usize = 180;
pub const MAX_USERNAME_LENGTH: usize = 30;

/** Get a random field element */
pub fn random_fr() -> ark_bn254::Fr {
    Fr::rand(&mut OsRng)
}
