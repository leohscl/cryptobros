use openssl::cipher::Cipher;
use openssl::cipher_ctx::CipherCtx;

pub fn c_str_to_bytes(c_str: &str) -> Vec<u8> {
    c_str.chars().map(|c| c as u8).collect()
}

pub fn bytes_as_string(bytes: &[u8]) -> String {
    bytes.into_iter().map(|&b| b as char).collect()
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

pub fn decrypt_ecb(to_decrypt: &[u8], key: &Vec<u8>) -> Vec<u8> {
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

// pub fn hex_to_byte_vec(hex: &str) -> Vec<u8> {
//     let chars: Vec<char> = hex.chars().collect();
//     chars
//         .chunks(2)
//         .map(|chunk| {
//             let c1 = chunk[0];
//             let c2 = chunk[1];
//             convert_hex_tuple_to_u8((c1, c2))
//         })
//         .collect()
// }
//
// fn convert_hex_tuple_to_u8(tuple_hex: (char, char)) -> u8 {
//     let first_4_bit = convert_hex_char_to_u8(tuple_hex.0);
//     let last_4_bit = convert_hex_char_to_u8(tuple_hex.1);
//     (first_4_bit << 4u8) + last_4_bit
// }
//
// fn convert_hex_char_to_u8(c: char) -> u8 {
//     let char_num = match c {
//         '0'..='9' => c as u8 - '0' as u8,
//         'a'..='f' => c as u8 - 'a' as u8 + 10u8,
//         _ => panic!("Input string is not in hexadecimal"),
//     };
//     char_num
// }
//
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
