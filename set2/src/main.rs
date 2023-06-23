mod utils;
use std::fs;
use utils::b64_to_bytes;
use utils::bytes_as_string;
use utils::c_str_to_bytes;
use utils::decrypt_ecb;
use utils::encrypt_ecb;
use utils::fixed_xor;

fn main() {
    ex9();
    ex10();
}

fn ex10() {
    // testing 0
    let key_string = "YELLOW SUBMARINE".to_string();
    let key = c_str_to_bytes(&key_string);
    // let file_contents = fs::read_to_string("data/encrypted_ECB_AES-128.txt").unwrap();
    // let contents = &file_contents.replace("\n", "");
    // let bytes = b64_to_bytes(&contents);
    let empty_vec = vec![];
    let encoded_padding_16 = encrypt_ecb(&empty_vec, &key);
    // let message = decrypt_ecb(&bytes, &key);
    // let decoded = bytes_as_string(&message);
    // dbg!(decoded);
    // let reencoded = encrypt_ecb(&message, &key);
    // assert!(reencoded == bytes);
    // testing 1
    // let padding_16: Vec<_> = std::iter::repeat(16u8).take(16).collect();
    // let mut trucated_encoded: Vec<u8> = bytes[0..16].into_iter().cloned().collect();
    // trucated_encoded.extend_from_slice(&encoded_padding_16);
    // let message_truncated = decrypt_ecb(&trucated_encoded, &key);
    // let decoded_truncated = bytes_as_string(&message_truncated);
    // dbg!(decoded_truncated);
    // let reencoded = encrypt_ecb(&message, &key);
    // assert!(reencoded == bytes);
    // testing 2
    // let key_string = "YELLOW SUBMARINE".to_string();
    // let key = c_str_to_bytes(&key_string);
    // let msg = "HELLO SUBMARIN".to_string();
    // let msg_bytes = c_str_to_bytes(&msg);
    // dbg!(msg_bytes.len());
    // let encoded_bytes = encrypt_ecb(&msg_bytes, &key);
    // dbg!(encoded_bytes.len());
    // dbg!(encoded_bytes.clone());
    // // let mut encoded_bytes_2: Vec<u8> = encoded_bytes[0..16].into_iter().cloned().collect();
    // // dbg!(encoded_bytes_2.len());
    // // pcks7_padding(&mut encoded_bytes_2, 16);
    // // dbg!(encoded_bytes_2.len());
    // let decoded_bytes = decrypt_ecb(&encoded_bytes, &key);
    // let msg_decoded = bytes_as_string(&decoded_bytes);
    // dbg!(&msg_decoded);
    // assert!(msg_decoded == msg);
    // testing 3
    // let file_contents = fs::read_to_string("data/encrypted_ECB_AES-128.txt").unwrap();
    // let contents = &file_contents.replace("\n", "");
    // let bytes = &b64_to_bytes(&contents)[..16];
    // let bytes_subset: Vec<_> = bytes[0..128]
    //     .into_iter()
    //     .cloned()
    //     .chain(bytes[(128 * 22)..2880].into_iter().cloned())
    //     .collect();
    // let message = decrypt_ecb(&bytes_subset, &key);
    // let decoded = bytes_as_string(&message);
    // dbg!(decoded);
    // let reencoded = encrypt_ecb(&message, &key);
    // assert!(reencoded == bytes);
    // decrypting file
    let file_contents = fs::read_to_string("data/encrypted_block_CBC.txt").unwrap();
    let contents = &file_contents.replace("\n", "");
    let bytes_encrypted = b64_to_bytes(&contents);
    // let first_block = &bytes_encrypted[0..16];
    // let test_with_first: Vec<_> = first_block
    //     .into_iter()
    //     .cloned()
    //     .chain(encoded_padding_16.into_iter())
    //     .collect();
    // let first_block_plain = decrypt_ecb(&test_with_first, &key);
    // let block_msg = bytes_as_string(&first_block_plain);
    // dbg!(block_msg);
    let iv = vec![0u8; key.len()];
    let decrypted_msg = decrypt_cbc(&bytes_encrypted, &key, &iv);
    let reencrypted = encrypt_cbc(&decrypted_msg, &key, &iv);
    dbg!(bytes_encrypted.len());
    dbg!(reencrypted.len());
    assert_eq!(bytes_encrypted, reencrypted);
    // let fixed = fixed_xor(&bytes_encrypted, &reencrypted);
    // dbg!(&fixed);
    // dbg!(fixed.into_iter().sum::<u8>());
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
