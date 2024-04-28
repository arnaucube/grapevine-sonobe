use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use ark_std::rand::rngs::OsRng;
use num_bigint::{BigInt, RandBigInt, Sign::Plus};
use std::error::Error;

use super::{MAX_SECRET_LENGTH, MAX_USERNAME_LENGTH, SECRET_FIELD_LENGTH};

#[derive(Clone, Debug)]
pub struct CircomPrivateInput {
    pub phrase: Option<String>,
    pub usernames: [Option<String>; 2],
    pub auth_secrets: [Option<BigInt>; 2],
    pub chaff: bool,
}

impl CircomPrivateInput {
    /**
     * Creates empty inputs
     *
     * @param chaff - if true, should compute random vars for chaff in circuit
     */
    pub fn empty(chaff: bool) -> Self {
        Self {
            phrase: None,
            usernames: [None, None],
            auth_secrets: [None, None],
            chaff,
        }
    }

    pub fn uninitialized(&self) -> bool {
        let not_chaff = self.phrase.is_none()
            && self.usernames.iter().all(|u| u.is_none())
            && self.auth_secrets.iter().all(|a| a.is_none());
        not_chaff && !self.chaff
    }
}

/** Get the starting ivc inputs (z0) for the grapevine circuit */
pub fn get_z0<F: PrimeField>() -> [F; 4] {
    (0..4)
        .map(|_| F::zero())
        .collect::<Vec<F>>()
        .try_into()
        .unwrap()
}

/** Generates a random field element for given field as bigint */
pub fn random_f_bigint<F: PrimeField>() -> BigInt {
    let lower_bound = BigInt::from(0);
    let upper_bound = BigInt::from_bytes_be(Plus, &F::MODULUS.to_bytes_be());
    OsRng.gen_bigint_range(&lower_bound, &upper_bound)
}

/**
 * Converts a given word to array of 6 field elements
 * @dev split into 31-byte strings to fit in finite field and pad with 0's where necessary
 *
 * @param phrase - the string entered by user to compute hash for (will be length checked)
 * @return - array of 6 Fr elements
 */
pub fn serialize_phrase(phrase: &String) -> Result<[BigInt; SECRET_FIELD_LENGTH], Box<dyn Error>> {
    // check length
    if phrase.len() > MAX_SECRET_LENGTH {
        return Err("Phrase must be <= 180 characters".into());
    }
    // convert each 31-byte chunk to field element
    let mut chunks: [BigInt; SECRET_FIELD_LENGTH] = Default::default();
    for i in 0..SECRET_FIELD_LENGTH {
        // get the range
        let start = i * 31;
        let end = (i + 1) * 31;
        let mut chunk: [u8; 32] = [0; 32];
        // select slice from range and pad if needed
        if start >= phrase.len() {
        } else if end > phrase.len() {
            chunk[1..(phrase.len() - start + 1)].copy_from_slice(&phrase.as_bytes()[start..]);
        } else {
            chunk[1..32].copy_from_slice(&phrase.as_bytes()[start..end]);
        }
        // wrap in field element
        chunks[i] = BigInt::from_bytes_be(Plus, &chunk);
    }
    Ok(chunks)
}

/**
* Converts a given username to a field element
*
* @param username - the username to convert to utf8 and into field element
* @return - the username serialied into the field element
*/
pub fn serialize_username(username: &String) -> Result<BigInt, Box<dyn Error>> {
    // check length
    if username.len() > MAX_USERNAME_LENGTH {
        return Err("Username must be <= 30 characters".into());
    }
    // convert to big endian bytes
    let mut bytes: [u8; 32] = [0; 32];
    bytes[1..(username.len() + 1)].copy_from_slice(&username.as_bytes()[..]);
    // convert to bigint
    Ok(BigInt::from_bytes_be(Plus, &bytes))
}

pub fn prepare_external_inputs<F: PrimeField>(inputs: &CircomPrivateInput) -> Vec<F> {
    // handle phrase presence (if not present infer chaff)
    let phrase = match &inputs.phrase {
        Some(phrase) => serialize_phrase(&phrase).unwrap().to_vec(),
        None => (0..6)
            .map(|_| random_f_bigint::<F>())
            .collect::<Vec<BigInt>>(),
    };

    // determine inputs: first step ([0] = None), Nth step ([1] = Some), and chaff ([2] = None)
    // marshal usernames
    let usernames = match inputs.usernames[0] {
        Some(_) => inputs
            .usernames
            .iter()
            .map(|u| serialize_username(&u.clone().unwrap()).unwrap())
            .collect::<Vec<BigInt>>(),
        None => match &inputs.usernames[1] {
            Some(username) => vec![BigInt::from(0), serialize_username(&username).unwrap()],
            None => vec![random_f_bigint::<F>(), random_f_bigint::<F>()],
        },
    };

    // marshal auth secrets
    let auth_sec = match inputs.auth_secrets[0] {
        Some(_) => inputs
            .auth_secrets
            .iter()
            .map(|a| a.clone().unwrap())
            .collect::<Vec<BigInt>>(),
        None => match &inputs.auth_secrets[1] {
            Some(auth_secret) => vec![BigInt::from(0), auth_secret.clone()],
            None => vec![random_f_bigint::<F>(), random_f_bigint::<F>()],
        },
    };

    // NOTE: probably wold be better that the inputs are prepared already as F instead of
    // BigInt (at the methods serialize_phrase, serialize_username).

    let inp: Vec<BigInt> = [phrase, usernames, auth_sec].concat();
    inp.iter()
        .map(|v| {
            let (_, b) = v.to_bytes_le();
            F::from_le_bytes_mod_order(&b)
        })
        .collect()
}
