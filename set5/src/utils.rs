use std::collections::HashMap;

use rand::Rng;

use openssl::cipher::Cipher;
use openssl::cipher_ctx::CipherCtx;

use sha1::{Digest, Sha1};

#[derive(Debug)]
pub struct PkcsError;

pub fn generate_aes_key() -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let mut key = Vec::new();
    for _ in 0..16 {
        let rand_byte: u8 = rng.gen();
        key.push(rand_byte);
    }
    key
}

pub fn c_str_to_bytes(c_str: &str) -> Vec<u8> {
    c_str.chars().map(|c| c as u8).collect()
}

pub fn bytes_as_string(bytes: &[u8]) -> String {
    bytes.into_iter().map(|&b| b as char).collect()
}

pub fn pkcs_validation(padded: &[u8]) -> Result<Vec<u8>, PkcsError> {
    let block_size = 16;
    let len = padded.len();
    let last = padded.iter().last().ok_or(PkcsError {})?;
    let num_padding = *last as usize;
    if num_padding > block_size || num_padding == 0 {
        return Err(PkcsError);
    }
    let candidate = padded.iter().take(len - num_padding).cloned().collect();
    let padding_validated = padded
        .into_iter()
        .skip(len - num_padding)
        .take(num_padding)
        .all(|byte| byte == last);
    match padding_validated {
        false => Err(PkcsError),
        true => Ok(candidate),
    }
}

pub fn decrypt_cbc(bytes_encrypted: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let iv_and_iter: Vec<u8> = iv
        .into_iter()
        .cloned()
        .chain(bytes_encrypted.into_iter().cloned())
        .collect();
    let empty_vec = vec![];
    let encoded_padding_16 = encrypt_ecb(&empty_vec, &key);
    // dbg!(encoded_padding_16.len());
    let chunks: Vec<_> = iv_and_iter.chunks(16).collect();
    // dbg!(chunks.len());
    let decoded: Vec<_> = chunks
        .windows(2)
        .flat_map(|slice_chunk| {
            let b1 = slice_chunk[0];
            let mut b2: Vec<u8> = slice_chunk[1].into_iter().cloned().collect();
            b2.extend_from_slice(&encoded_padding_16);
            let decoded = decrypt_ecb(&b2, key);
            let plain = fixed_xor(&decoded[0..16], b1);
            plain.into_iter()
        })
        .collect();
    // dbg!(decoded.len());
    decoded
}

pub fn encrypt_cbc(to_encrypt: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let mut vec_to_encrypt: Vec<_> = to_encrypt.into_iter().cloned().collect();
    pcks7_padding(&mut vec_to_encrypt, 16);
    let vec_iv: Vec<_> = iv.into_iter().cloned().collect();
    let chunks: Vec<_> = vec_to_encrypt.chunks(16).collect();
    let mut last_coded_chunk = vec_iv;
    let mut encoded = vec![];
    for chunk in chunks {
        let xor = fixed_xor(&last_coded_chunk, chunk);
        let new_encoded = encrypt_ecb(&xor, key);
        encoded.extend_from_slice(&new_encoded[0..16]);
        last_coded_chunk = new_encoded;
    }
    encoded
}

pub fn encrypt_ecb(to_encrypt: &[u8], key: &[u8]) -> Vec<u8> {
    let cipher = Cipher::aes_128_ecb();
    let mut ctx = CipherCtx::new().unwrap();
    ctx.encrypt_init(Some(cipher), Some(&key), None).unwrap();
    let mut plaintext = vec![];
    ctx.cipher_update_vec(&to_encrypt, &mut plaintext).unwrap();
    ctx.cipher_final_vec(&mut plaintext).unwrap();
    plaintext
}

pub fn instanciate_hash_frequency() -> HashMap<char, f64> {
    let mut hashmap = HashMap::new();
    hashmap.insert('e', 0.11);
    hashmap.insert('a', 0.085);
    // hashmap.insert('r', 0.07);
    // hashmap.insert('i', 0.07);
    // hashmap.insert('t', 0.07);
    // hashmap.insert(' ', 0.16);
    hashmap
}

pub fn score_string(decoded: &str, char_freq: &HashMap<char, f64>) -> f64 {
    let length = decoded.len();
    let mut score = 0f64;
    for c_test in char_freq.keys() {
        let sum_decode = decoded
            .chars()
            .map(|c| if c == *c_test { 1 } else { 0 })
            .sum::<u32>();
        let freq = sum_decode as f64 / length as f64;
        let score_letter = get_score_freq(char_freq.get(c_test).cloned(), freq);
        score += score_letter;
    }
    let sum_alpha = decoded
        .chars()
        .map(|c| if 'a' <= c && c <= 'z' { -1f64 } else { 0f64 })
        .sum::<f64>()
        / decoded.len() as f64;
    score + sum_alpha
}

fn get_score_freq(computed_freq: Option<f64>, reference_freq: f64) -> f64 {
    if let Some(freq) = computed_freq {
        (freq - reference_freq).abs()
    } else {
        0f64
    }
}

pub fn decrypt_ecb(to_decrypt: &[u8], key: &[u8]) -> Vec<u8> {
    let cipher = Cipher::aes_128_ecb();
    let mut ctx = CipherCtx::new().unwrap();
    // dbg!(to_decrypt.len());
    // dbg!(key.len());
    ctx.decrypt_init(Some(cipher), Some(&key), None).unwrap();
    let mut plaintext = vec![];
    ctx.cipher_update_vec(&to_decrypt, &mut plaintext).unwrap();
    ctx.cipher_final_vec(&mut plaintext).unwrap();
    plaintext
}

pub fn b64_to_bytes(b64: &str) -> Vec<u8> {
    let vec_char: Vec<_> = b64.chars().collect();
    vec_char
        .chunks(4)
        .flat_map(move |chunk| {
            let mut result = 0u32;
            let mut cur_num_bytes_decode = 3;
            for letter_i in 0..=3 {
                let letter = chunk[letter_i];
                if letter == '=' {
                    cur_num_bytes_decode -= 1;
                } else {
                    let bits_i = letter_to_6_bits(letter) as u32;
                    let tmp = bits_i << (6 * (3 - letter_i));
                    result += tmp;
                }
            }
            let mask = 2u32.pow(8) - 1;
            let bytes: Vec<_> = (0..cur_num_bytes_decode)
                .map(|byte_i| {
                    let byte = result >> ((2 - byte_i) * 8) & mask;
                    byte as u8
                })
                .collect();
            bytes.into_iter()
        })
        .collect()
}
fn letter_to_6_bits(letter: char) -> u8 {
    match letter {
        'A'..='Z' => letter as u8 - 'A' as u8,
        'a'..='z' => letter as u8 - 'a' as u8 + 26u8,
        '0'..='9' => letter as u8 - '0' as u8 + 52u8,
        '+' => 62,
        '/' => 63,
        _ => panic!("input char invalid"),
    }
}

pub fn fixed_xor(bytes_1: &[u8], bytes_2: &[u8]) -> Vec<u8> {
    bytes_1
        .into_iter()
        .zip(bytes_2.into_iter())
        .map(|(b1, b2)| b1 ^ b2)
        .collect()
}

pub fn hex_to_byte_vec(hex: &str) -> Vec<u8> {
    let chars: Vec<char> = hex.chars().collect();
    chars
        .chunks(2)
        .map(|chunk| {
            let c1 = chunk[0];
            let c2 = chunk[1];
            convert_hex_tuple_to_u8((c1, c2))
        })
        .collect()
}
fn convert_hex_tuple_to_u8(tuple_hex: (char, char)) -> u8 {
    let first_4_bit = convert_hex_char_to_u8(tuple_hex.0);
    let last_4_bit = convert_hex_char_to_u8(tuple_hex.1);
    (first_4_bit << 4u8) + last_4_bit
}

fn convert_hex_char_to_u8(c: char) -> u8 {
    let char_num = match c {
        '0'..='9' => c as u8 - '0' as u8,
        'a'..='f' => c as u8 - 'a' as u8 + 10u8,
        _ => panic!("Input string is not in hexadecimal"),
    };
    char_num
}

pub fn has_repeating_bytes(vec_bytes: Vec<u8>) -> bool {
    // dbg!(vec_bytes.len());
    // detect repeats
    let bytes_copy = vec_bytes.clone();
    let repeated_block = vec_bytes
        .chunks(16)
        .enumerate()
        .map(|(index_left, slice_ref)| {
            bytes_copy
                .chunks(16)
                .enumerate()
                .filter_map(|(index_right, slice_test)| {
                    if index_left == index_right {
                        None
                    } else {
                        Some(slice_test)
                    }
                })
                .any(|slice_test| slice_ref == slice_test)
        })
        .any(|repeated| repeated);
    repeated_block
}

pub fn pcks7_padding(block: &mut Vec<u8>, block_size: usize) {
    let length = block.len();
    let factor = length / block_size;
    let multiple_bigger = block_size * (factor + 1);
    let number_bytes_pad = multiple_bigger - length;
    let padding = std::iter::repeat(number_bytes_pad as u8).take(number_bytes_pad);
    block.extend(padding);
}

pub fn hash_input(input: &[u8]) -> Vec<u8> {
    // create a Sha1 object
    let mut hasher = Sha1::new();

    // process input message
    hasher.update(input);

    // acquire hash digest in the form of GenericArray,
    // which in this case is equivalent to [u8; 20]
    let result = hasher.finalize();
    result.to_vec()
}
