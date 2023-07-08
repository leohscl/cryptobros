mod utils;

use std::collections::HashMap;

use rand::Rng;
use utils::c_str_to_bytes;
use utils::decrypt_cbc;
use utils::encrypt_cbc;
use utils::encrypt_ecb;
use utils::fixed_xor;
use utils::generate_aes_key;
use utils::pcks7_padding;
use utils::pkcs_validation;

use crate::utils::b64_to_bytes;
use crate::utils::bytes_as_string;

static mut KEY: Vec<u8> = Vec::new();

static COOKIE_STRING: [&str; 10] = [
    "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
    "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
    "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
    "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
    "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
    "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
    "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
    "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
    "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
    "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
];

fn main() {
    let random_key = generate_aes_key();
    unsafe {
        KEY = random_key;
    }
    ex17();
    ex18();
    ex19();
}

fn ex19() {
    let end_decrypt = 17;
    let input_to_encrypt = include_str!("../data/input_ctr_to_encrypt.txt");
    let encryptions: Vec<Vec<u8>> = input_to_encrypt
        .trim_end_matches('\n')
        .split('\n')
        .into_iter()
        .map(|input| ctr_encrypt_fixed(&b64_to_bytes(&input)))
        .collect();
    // sets of letters that were xor'd against the same byte
    let concordant_letters: Vec<Vec<u8>> = (0..=end_decrypt)
        .map(|index| {
            encryptions
                .iter()
                .map(|encrypted| encrypted.into_iter().nth(index).unwrap())
                .cloned()
                .collect()
        })
        .collect();
    // we guess a byte for each concordant letter set
    let hash_frequency = utils::instanciate_hash_frequency();
    let mut potential_ciphertext: Vec<u8> = concordant_letters
        .into_iter()
        .map(|set| {
            // score each byte
            let min_pair = (0..255)
                .into_iter()
                .map(|byte_test| {
                    (
                        byte_test,
                        score_xor_candidate(&set, byte_test, &hash_frequency),
                    )
                })
                .min_by(|t1, t2| t1.1.total_cmp(&t2.1))
                .unwrap();
            dbg!(&min_pair);
            min_pair.0
        })
        .collect();

    // ad-hoc decryption looking at strings
    potential_ciphertext[0] ^= 'n' as u8;
    potential_ciphertext[0] ^= 'i' as u8;
    let plaintext_bytes: Vec<Vec<u8>> = encryptions
        .into_iter()
        .map(|encrypted_bytes| {
            let encrypted_start = &encrypted_bytes[0..=end_decrypt];
            fixed_xor(encrypted_start, &potential_ciphertext)
        })
        .collect();
    plaintext_bytes.into_iter().for_each(|plaintext| {
        dbg!(bytes_as_string(&plaintext));
    })
}

// fn get_trigram_hash() -> HashMap<String, f64> {
//     let mut hash_trigram = HashMap::new();
//     hash_trigram.insert("the".to_string(), 0.03508232);
//     hash_trigram.insert("and".to_string(), 0.01593878);
//     hash_trigram.insert("ing".to_string(), 0.01147042);
//     hash_trigram.insert("her".to_string(), 0.00822444);
//     hash_trigram.insert("hat".to_string(), 0.00650715);
//     hash_trigram.insert("his".to_string(), 0.00596748);
//     hash_trigram.insert("tha".to_string(), 0.00593593);
//     hash_trigram.insert("ere".to_string(), 0.00560594);
//     hash_trigram.insert("for".to_string(), 0.00555372);
//     hash_trigram.insert("ent".to_string(), 0.00530771);
//     hash_trigram.insert("ion".to_string(), 0.00506454);
//     hash_trigram.insert("ter".to_string(), 0.00461099);
//     hash_trigram.insert("was".to_string(), 0.00460487);
//     hash_trigram.insert("you".to_string(), 0.00437213);
//     hash_trigram.insert("ith".to_string(), 0.00431250);
//     hash_trigram.insert("ver".to_string(), 0.00430732);
//     hash_trigram.insert("all".to_string(), 0.00422758);
//     hash_trigram.insert("wit".to_string(), 0.00397290);
//     hash_trigram.insert("thi".to_string(), 0.00394796);
//     hash_trigram.insert("tio".to_string(), 0.00378058);
//     hash_trigram
// }

fn count_trigram(b1: u8, b2: u8, b3: u8, hash_bigram: &HashMap<String, f64>) -> f64 {
    let vec_bytes = vec![b1, b2, b3];
    let input_trigram = bytes_as_string(&vec_bytes);
    *hash_bigram.get(&input_trigram).unwrap_or(&0f64)
}

fn score_xor_candidate(bytes_letters: &[u8], byte_test: u8, char_freq: &HashMap<char, f64>) -> f64 {
    let mut bytes_letters_copy: Vec<u8> = bytes_letters.into_iter().cloned().collect();
    for byte in bytes_letters_copy.iter_mut() {
        *byte ^= byte_test;
    }
    let string_candidate = bytes_as_string(&bytes_letters_copy);
    let score = utils::score_string(&string_candidate, char_freq);
    // dbg!(score);
    score
}

fn ex18() {
    let key = c_str_to_bytes("YELLOW SUBMARINE");
    let encrypted = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==";
    let bytes_encrypted = b64_to_bytes(encrypted);
    let decrypted = ctr_encrypt(&bytes_encrypted, &key, 0);
    dbg!(bytes_as_string(&decrypted));
}

fn ctr_encrypt_fixed(to_encode: &[u8]) -> Vec<u8> {
    let nonce = 0;
    let key;
    unsafe {
        key = KEY.clone();
    }
    ctr_encrypt(to_encode, &key, nonce)
}

fn ctr_encrypt(to_encode: &[u8], key: &[u8], nonce: u64) -> Vec<u8> {
    // let block_size = 16;
    // let num_block = length_encode / block_size + 1;
    let length_encode = to_encode.len();
    let stream_cipher: Vec<u8> = (0..)
        .into_iter()
        .flat_map(|counter: u64| {
            let bytes_count = counter.to_le_bytes();
            let bytes_nonce = nonce.to_le_bytes();
            let to_encrypt_ecb = [bytes_nonce, bytes_count].concat();
            let encoded_stream = encrypt_ecb(&to_encrypt_ecb, key);
            encoded_stream.into_iter().take(16)
        })
        .take(length_encode)
        .collect();
    fixed_xor(to_encode, &stream_cipher)
}

fn ex17() {
    let (iv, encoded) = encode_cookie();
    let decoded = padding_oracle_attack(&encoded, &iv);
    dbg!(bytes_as_string(&decoded));
}

fn padding_oracle_attack(encoded: &[u8], iv: &[u8]) -> Vec<u8> {
    let cipher_with_iv: Vec<u8> = iv
        .into_iter()
        .cloned()
        .chain(encoded.into_iter().cloned())
        .collect();
    cipher_with_iv
        .windows(32)
        .step_by(16)
        .flat_map(|slice| {
            let slice_1 = &slice[0..16];
            let slice_2 = &slice[16..32];
            let plain_bytes = padding_oracle_core(slice_1, slice_2);
            // dbg!(bytes_as_string(&plain_bytes));
            plain_bytes.into_iter()
        })
        .collect()
}

fn padding_oracle_core(c1: &[u8], c2: &[u8]) -> Vec<u8> {
    let mut plain_bytes = vec![0u8; 16];
    assert_eq!(c1.len(), c2.len());
    let mut corrupted_encrypt: Vec<u8> = c1.into_iter().cloned().collect();
    for target_byte_index in (0..=15).rev() {
        let padding_target = 16 - target_byte_index;
        for potential_decrypt in 0..=255 {
            corrupted_encrypt[target_byte_index] ^= potential_decrypt;
            let has_valid_padding = decode_cbc_check_padding(c2, &corrupted_encrypt);
            // if we change the next bit and it is not valid, keep going
            if has_valid_padding {
                if target_byte_index > 0 {
                    corrupted_encrypt[target_byte_index - 1] ^= 1;
                }
                if decode_cbc_check_padding(c2, &corrupted_encrypt) {
                    if target_byte_index > 0 {
                        corrupted_encrypt[target_byte_index - 1] ^= 1;
                    }
                    let plain_byte = padding_target as u8 ^ potential_decrypt;
                    plain_bytes[target_byte_index] = plain_byte;
                    for old_target in (target_byte_index..=15).rev() {
                        corrupted_encrypt[old_target] ^= padding_target as u8;
                        corrupted_encrypt[old_target] ^= (padding_target + 1) as u8;
                    }
                    break;
                }
                // undo previous operation
                corrupted_encrypt[target_byte_index - 1] ^= 1;
            }
            corrupted_encrypt[target_byte_index] ^= potential_decrypt;
        }
    }
    plain_bytes
}

fn decode_cbc_check_padding(input: &[u8], iv: &[u8]) -> bool {
    let key;
    unsafe {
        key = KEY.clone();
    }
    let bytes_decrypted = decrypt_cbc(input, &key, iv);
    // dbg!(bytes_as_string(&bytes_decrypted));
    pkcs_validation(&bytes_decrypted).is_ok()
}

fn encode_cookie() -> (Vec<u8>, Vec<u8>) {
    let mut rng = rand::thread_rng();
    let index_str = rng.gen_range(0..=9);
    let string_encode = COOKIE_STRING[index_str];
    let bytes_input = b64_to_bytes(&string_encode);
    let iv = generate_aes_key();
    let encoded = encode_cbc_padded(&bytes_input, &iv);
    (iv, encoded)
}

fn encode_cbc_padded(input: &[u8], iv: &[u8]) -> Vec<u8> {
    let key;
    unsafe {
        key = KEY.clone();
    }
    let mut bytes_input: Vec<u8> = input.into_iter().cloned().collect();
    pcks7_padding(&mut bytes_input, 16);
    encrypt_cbc(&bytes_input, &key, iv)
}
