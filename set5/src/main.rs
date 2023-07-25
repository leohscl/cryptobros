mod utils;

use utils::{encrypt_cbc, hex_to_byte_vec};
use utils::{generate_aes_key, hash_input};

use color_eyre::Result;
use num_bigint::BigUint;
use num_bigint::RandBigInt;
use num_bigint::ToBigUint;
use rand::Rng;
use sha256::digest;

use crate::utils::{bytes_as_string, decrypt_cbc, pkcs_validation};

fn main() -> Result<()> {
    color_eyre::install()?;
    ex33();
    ex34();
    ex35();
    Ok(())
}

fn ex35() {
    let hex_n = "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024\
                 e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd\
                 3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec\
                 6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f\
                 24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361\
                 c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552\
                 bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff\
                 fffffffffffff";
    let n = hex_to_biguint(hex_n);
    let g = 2.to_biguint().unwrap();
    let k = 3.to_biguint().unwrap();
    let email = "leo.henches@gmail.com";
    let password = "azerty";

    // S
    let mut rng = rand::thread_rng();
    let b = rng.gen_biguint_range(&0u32.to_biguint().unwrap(), &n);
    let salt = rand::thread_rng().gen_range(0..128);
    let string_to_digest = salt.to_string() + password;
    let digest = sha256::digest(string_to_digest);
    let digest_as_num = hex_to_biguint(&digest);
    let v = mod_exp_bignum(g.clone(), digest_as_num, n.clone());
    drop(digest);

    // C
    let mut rng = rand::thread_rng();
    let a = rng.gen_biguint_range(&0u32.to_biguint().unwrap(), &n);
    // C -> S
    let big_a = mod_exp_bignum(g.clone(), a.clone(), n.clone());
    // send big_a

    // S -> C
    // send salt
    let big_b = k.clone() * v.clone() + mod_exp_bignum(g.clone(), b.clone(), n.clone());
    // send big_b

    // both
    let digest_big = sha256::digest(big_a.to_string() + &big_b.to_string());
    let digest_big_num = hex_to_biguint(&digest_big);

    // C
    let string_to_digest = salt.to_string() + password;
    let digest = sha256::digest(string_to_digest);
    let digest_as_num = hex_to_biguint(&digest);
    let inter_s = big_b - k.clone() * mod_exp_bignum(g.clone(), digest_as_num.clone(), n.clone());
    let s = mod_exp_bignum(
        inter_s,
        a + digest_big_num.clone() * digest_as_num.clone(),
        n.clone(),
    );
    let k = sha256::digest(s.to_bytes_le());

    // S
    let s_inter_s = mod_exp_bignum(v, digest_big_num.clone(), n.clone());
    let s_s = mod_exp_bignum(big_a * s_inter_s, b, n.clone());
    let k_s = sha256::digest(s_s.to_bytes_le());
    assert_eq!(s_s, s);
    assert_eq!(k_s, k);
}

struct Chatter {
    secret: BigUint,
    p: BigUint,
    s: Option<BigUint>,
}

impl Chatter {
    fn generate_a(g: &BigUint, p: &BigUint) -> (Chatter, BigUint) {
        let mut rng = rand::thread_rng();
        let a = rng.gen_biguint_range(&0u32.to_biguint().unwrap(), &p);
        let big_a = mod_exp_bignum(g.clone(), a.clone(), p.clone());
        (
            Chatter {
                secret: a,
                p: p.clone(),
                s: None,
            },
            big_a,
        )
    }

    fn generate_b(g: BigUint, p: BigUint, big_a: BigUint) -> (Chatter, BigUint) {
        let mut rng = rand::thread_rng();
        let b = rng.gen_biguint_range(&0u32.to_biguint().unwrap(), &p);
        // let big_a = mod_exp_bignum(g.clone(), chatter_a.secret.clone(), p.clone());
        let s = mod_exp_bignum(big_a.clone(), b.clone(), p.clone());
        // generate big_b for A
        let big_b = mod_exp_bignum(g.clone(), b.clone(), p.clone());
        (
            Chatter {
                secret: b,
                p,
                s: Some(s),
            },
            big_b,
        )
    }

    fn update_a_with_big_b(&mut self, b_big: BigUint) {
        let s = mod_exp_bignum(b_big, self.secret.clone(), self.p.clone());
        self.s = Some(s);
    }

    fn a_send_encoding(&self) -> (Vec<u8>, Vec<u8>) {
        let message = b"hello world";
        let s = self.s.clone().unwrap();
        let sha_encoding = hash_input(&s.to_bytes_le());
        let sha_truncated = &sha_encoding.as_slice()[0..16];
        let iv = generate_aes_key();
        let encrypted = encrypt_cbc(message, sha_truncated, &iv);
        (encrypted, iv)
    }

    fn b_decrypt_message(&self, message_hash: &[u8], iv: &[u8]) {
        let s = self.s.clone().unwrap();
        let sha_encoding = hash_input(&s.to_bytes_le());
        let sha_truncated = &sha_encoding.as_slice()[0..16];
        // let iv = generate_aes_key();
        let decrypted = pkcs_validation(&decrypt_cbc(message_hash, sha_truncated, &iv)).unwrap();
        assert_eq!(decrypted, b"hello world");
    }
}

fn decrypt_msg_mitm(message_hash: &[u8], iv: &[u8]) {
    let s = 0.to_biguint().unwrap();
    let sha_encoding = hash_input(&s.to_bytes_le());
    let sha_truncated = &sha_encoding.as_slice()[0..16];
    let decrypted_mitm = pkcs_validation(&decrypt_cbc(message_hash, sha_truncated, &iv)).unwrap();
    dbg!(bytes_as_string(&decrypted_mitm));
    assert_eq!(decrypted_mitm, b"hello world");
}

fn ex34() {
    let hex_p = "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024\
                 e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd\
                 3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec\
                 6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f\
                 24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361\
                 c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552\
                 bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff\
                 fffffffffffff";
    let p = hex_to_biguint(hex_p);
    let g = 2.to_biguint().unwrap();

    let (mut chatter_a, big_a) = Chatter::generate_a(&g, &p);
    // A -> B key
    // B saves s, sends key
    let (chatter_b, big_b) = Chatter::generate_b(g.clone(), p.clone(), big_a.clone());
    // A saves s key using big_b
    chatter_a.update_a_with_big_b(big_b);

    assert_eq!(chatter_a.s, chatter_b.s);
    // A -> B hello
    let (encrypted, iv1) = chatter_a.a_send_encoding();
    // // B saves encrypted and iv1
    // // B decrypts
    chatter_b.b_decrypt_message(&encrypted, &iv1);
    // // A -> B
    //
    // now with MITM
    // A -> M
    let (mut chatter_a, _big_a) = Chatter::generate_a(&g, &p);
    // M swaps big_a
    let (chatter_b, _big_b) = Chatter::generate_b(g.clone(), p.clone(), p.clone());
    // M intercepts big_b
    chatter_a.update_a_with_big_b(p);

    let (encrypted, iv1) = chatter_a.a_send_encoding();
    chatter_b.b_decrypt_message(&encrypted, &iv1);

    // s = p.pow(b)
    decrypt_msg_mitm(&encrypted, &iv1);

    // let j
}

fn ex33() {
    let mut rng = rand::thread_rng();
    let p = 37u32;
    let g = 5u32;
    let a = rng.gen_range(0..p);
    let b = rng.gen_range(0..p);
    let big_a = mod_exp(g, a, p);
    let big_b = mod_exp(g, b, p);
    let s = mod_exp(big_b, a, p);
    assert_eq!(s, mod_exp(big_a, b, p));

    let hex_p_test = "25";
    let hex_g_test = "05";
    let p_big = hex_to_biguint(hex_p_test);
    let g_big = hex_to_biguint(hex_g_test);
    let b_biguint = b.to_biguint().unwrap();
    assert_eq!(
        big_b.to_biguint().unwrap(),
        mod_exp_bignum(g_big, b_biguint.clone(), p_big)
    );

    let a_biguint = a.to_biguint().unwrap();
    // real parameters
    let hex_p = "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024\
                 e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd\
                 3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec\
                 6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f\
                 24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361\
                 c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552\
                 bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff\
                 fffffffffffff";
    let p = hex_to_biguint(hex_p);
    let g = hex_to_biguint("02");
    let big_a = mod_exp_bignum(g.clone(), a_biguint.clone(), p.clone());
    let big_b = mod_exp_bignum(g.clone(), b_biguint.clone(), p.clone());
    let s = mod_exp_bignum(big_a, b_biguint, p.clone());
    assert_eq!(s, mod_exp_bignum(big_b, a_biguint, p));
}

fn hex_to_biguint(hex: &str) -> BigUint {
    let bytes_hex = hex_to_byte_vec(hex);
    BigUint::from_bytes_le(&bytes_hex)
}

fn mod_exp_bignum(number: BigUint, power: BigUint, modulus: BigUint) -> BigUint {
    let mut current_result = 1u32.to_biguint().unwrap();
    let mut current_exponent = 0u32;
    let mut current_mod_value = number.clone() % modulus.clone();
    let result = loop {
        let current_2_power = 1.to_biguint().unwrap() << current_exponent;
        if ((power.clone() >> current_exponent) % 2.to_biguint().unwrap())
            == 1.to_biguint().unwrap()
        {
            current_result = (current_result * current_mod_value.clone()) % modulus.clone()
        }
        if current_2_power > power.clone() {
            break current_result;
        }
        current_exponent += 1;
        current_mod_value =
            (current_mod_value.clone() * current_mod_value.clone()) % modulus.clone();
    };
    result
}

fn mod_exp(number: u32, power: u32, modulus: u32) -> u32 {
    let mut counter_mult = 0;
    let mut current_result = 1;
    while counter_mult != power {
        counter_mult += 1;
        current_result = (current_result * number) % modulus;
    }
    current_result
}
