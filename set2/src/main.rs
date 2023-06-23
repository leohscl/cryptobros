mod utils;
use rand::Rng;
use std::collections::HashMap;
use std::fs;
use utils::b64_to_bytes;
use utils::bytes_as_string;
use utils::c_str_to_bytes;
use utils::decrypt_ecb;
use utils::encrypt_ecb;
use utils::fixed_xor;
use utils::has_repeating_bytes;

fn main() {
    ex9();
    ex10();
    ex11();
    ex12();
}

fn ex12() {
    let unknown_key = generate_aes_key();
    let unknown_b64 = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg\
                        aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq\
                        dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg\
                        YnkK";
    let unknown_message = b64_to_bytes(unknown_b64);
    let plain_bytes = decipher_using_oracle(&unknown_message, &unknown_key);
    dbg!(bytes_as_string(&plain_bytes));
}

fn decipher_using_oracle(unknown_message: &Vec<u8>, unknown_key: &Vec<u8>) -> Vec<u8> {
    let block_size = get_block_size_bytes(&unknown_message, &unknown_key);
    // dbg!(block_size);
    let repeated_bytes: Vec<u8> = std::iter::repeat(0u8).take(block_size * 4).collect();
    let encode_repetition = encryption_oracle_ecb(&repeated_bytes, &unknown_message, &unknown_key);
    let is_ecb = has_repeating_bytes(encode_repetition);
    // dbg!(is_ecb);
    let mut decoded_bytes = vec![];
    assert!(block_size >= 2);
    if is_ecb {
        while decoded_bytes.len() != unknown_message.len() {
            let length_decoded_needed = decoded_bytes.len() % block_size;
            let short_1_byte: Vec<u8> = std::iter::repeat(0u8)
                .take(block_size - 1 - length_decoded_needed)
                .chain(decoded_bytes.iter().cloned().take(length_decoded_needed))
                .collect();
            // dbg!(&short_1_byte);
            let mut all_potential_encoding = HashMap::new();
            let remaining_encoded = &unknown_message[decoded_bytes.len()..];
            for potential_byte in 0..255 {
                let plain_test: Vec<_> = short_1_byte
                    .iter()
                    .cloned()
                    .chain(std::iter::once(potential_byte))
                    .collect();
                let potential_encoding =
                    encryption_oracle_ecb(&plain_test, remaining_encoded, &unknown_key);
                let first_block_plain: Vec<_> = plain_test.into_iter().take(block_size).collect();
                let first_block_encoded: Vec<_> =
                    potential_encoding.into_iter().take(block_size).collect();
                all_potential_encoding.insert(first_block_encoded, first_block_plain);
            }

            let encode_1_byte_hidden =
                encryption_oracle_ecb(&short_1_byte, remaining_encoded, &unknown_key);
            let first_block_encoded_1_byte_hidden: Vec<_> =
                encode_1_byte_hidden.into_iter().take(block_size).collect();
            let first_block_plain_1_byte_hidden = all_potential_encoding
                .get(&first_block_encoded_1_byte_hidden)
                .unwrap();
            let plain_byte = first_block_plain_1_byte_hidden.last().unwrap();
            decoded_bytes.push(*plain_byte);
        }
    } else {
        panic!("Not ecb !");
    }
    decoded_bytes
    // todo!()
}

fn get_block_size_bytes(unknown_message: &Vec<u8>, unknown_key: &Vec<u8>) -> usize {
    let encryption_base_size = encryption_oracle_ecb(&vec![], unknown_message, unknown_key).len();
    let mut encryption_next_size;
    let mut count = 1;
    let byte_difference = loop {
        let prepend: Vec<_> = std::iter::repeat(0u8).take(count).collect();
        encryption_next_size = encryption_oracle_ecb(&prepend, unknown_message, unknown_key).len();
        if encryption_base_size != encryption_next_size {
            break (encryption_next_size - encryption_base_size);
        }
        count += 1;
    };
    byte_difference
}

fn encryption_oracle_ecb(prepend_text: &[u8], plain_bytes: &[u8], unknown_key: &[u8]) -> Vec<u8> {
    let to_encrypt: Vec<_> = prepend_text
        .into_iter()
        .chain(plain_bytes.into_iter())
        .cloned()
        .collect();
    encrypt_ecb(&to_encrypt, unknown_key)
}

fn ex11() {
    let message = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string();
    let bytes_msg = c_str_to_bytes(&message);
    for _ in 0..10 {
        let (ecb_used, encrypted) = encryption_oracle(bytes_msg.clone());
        assert!(ecb_used == has_repeating_bytes(encrypted));
    }
}

fn generate_5_10_bytes() -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let mut bytes = Vec::new();
    let number = rng.gen_range(5..=10) as usize;
    for _ in 0..number {
        let rand_byte: u8 = rng.gen();
        bytes.push(rand_byte);
    }
    bytes
}

fn generate_aes_key() -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let mut key = Vec::new();
    for _ in 0..16 {
        let rand_byte: u8 = rng.gen();
        key.push(rand_byte);
    }
    key
}

fn encryption_oracle(bytes: Vec<u8>) -> (bool, Vec<u8>) {
    let mut rng = rand::thread_rng();
    let random_prefix = generate_5_10_bytes();
    let random_suffix = generate_5_10_bytes();
    let to_encrypt: Vec<_> = random_prefix
        .into_iter()
        .chain(bytes.into_iter())
        .chain(random_suffix.into_iter())
        .collect();

    let key = generate_aes_key();
    let use_ecb = rng.gen_bool(0.5);
    let encrypted = if use_ecb {
        encrypt_ecb(&to_encrypt, &key)
    } else {
        let random_iv = generate_aes_key();
        encrypt_cbc(&to_encrypt, &key, &random_iv)
    };
    (use_ecb, encrypted)
}

fn ex10() {
    // testing 0
    let key_string = "YELLOW SUBMARINE".to_string();
    let key = c_str_to_bytes(&key_string);
    let file_contents = fs::read_to_string("data/encrypted_block_CBC.txt").unwrap();
    let contents = &file_contents.replace("\n", "");
    let bytes_encrypted = b64_to_bytes(&contents);
    let iv = vec![0u8; key.len()];
    let decrypted_msg = decrypt_cbc(&bytes_encrypted, &key, &iv);
    let reencrypted = encrypt_cbc(&decrypted_msg, &key, &iv);
    // dbg!(bytes_encrypted.len());
    // dbg!(reencrypted.len());
    assert_eq!(bytes_encrypted, reencrypted);
    let msg_as_txt = bytes_as_string(&decrypted_msg);
    dbg!(msg_as_txt);
}

fn encrypt_cbc(to_encrypt: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let vec_to_encrypt: Vec<_> = to_encrypt.into_iter().cloned().collect();
    // pcks7_padding(&mut vec_to_encrypt, 16);
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

fn decrypt_cbc(bytes_encrypted: &[u8], key: &Vec<u8>, iv: &Vec<u8>) -> Vec<u8> {
    let iv_and_iter: Vec<u8> = iv
        .into_iter()
        .cloned()
        .chain(bytes_encrypted.into_iter().cloned())
        .collect();
    let empty_vec = vec![];
    let encoded_padding_16 = encrypt_ecb(&empty_vec, &key);
    let chunks: Vec<_> = iv_and_iter.chunks(16).collect();
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
    decoded
}

fn ex9() {
    let to_pad = "YELLOW SUBMARINE".to_string();
    let mut bytes_to_pad = c_str_to_bytes(&to_pad);
    pcks7_padding(&mut bytes_to_pad, 20);
    let padded_string = bytes_as_string(&bytes_to_pad);
    dbg!(padded_string);
}

fn pcks7_padding(block: &mut Vec<u8>, block_size: usize) {
    let length = block.len();
    let factor = length / block_size;
    let multiple_bigger = block_size * (factor + 1);
    let number_bytes_pad = multiple_bigger - length;
    let padding = std::iter::repeat(number_bytes_pad as u8).take(number_bytes_pad);
    block.extend(padding);
}
