use openssl::cipher::Cipher;
use openssl::cipher_ctx::CipherCtx;
use std::collections::HashMap;
use std::fs;

fn main() {
    // ex1();
    // ex2();
    // ex4();
    // ex5();
    // ex6();
    // ex7();
    ex8();
}

fn decrypt_repeating_xor(bytes: &Vec<u8>) -> String {
    let keysize_candidate = get_min_hamming(&bytes);
    let vec_blocks: Vec<String> = (0..keysize_candidate)
        .map(|skip| {
            bytes
                .iter()
                .skip(skip)
                .step_by(keysize_candidate)
                .flat_map(|byte| {
                    let (c1, c2) = convert_u8_to_hex_tuple(*byte);
                    [c1, c2].into_iter()
                })
                .collect()
        })
        .collect();

    let char_freq = instanciate_hash_frequency();
    let keys: Vec<_> = vec_blocks
        .into_iter()
        .map(|str_coded| get_min_message_decode(&str_coded, &char_freq).2)
        .collect();
    let string_keys: String = keys.into_iter().map(|k| k as char).collect();
    let bytes_decoded = encrypt_message_repeating_xor(&bytes, &string_keys);
    let string_decoded: String = bytes_decoded.into_iter().map(|b| b as char).collect();
    string_decoded
}

fn get_min_hamming(bytes: &Vec<u8>) -> usize {
    // let vec_hamming_with_size: Vec<_> = (2..=4)
    let vec_hamming_with_size: Vec<_> = (1..40)
        .map(|keysize| {
            let max_chunk_bytes = bytes.len() / keysize;
            let mut iter_bytes = bytes.iter();
            let mut_ref_iter = iter_bytes.by_ref();
            let bytes_first: Vec<u8> = mut_ref_iter.take(keysize).cloned().collect();
            let hamming_candidate: f64 = (1..max_chunk_bytes)
                .map(|_| {
                    let bytes_current: Vec<u8> = mut_ref_iter.take(keysize).cloned().collect();
                    let hamming = hamming_distance_bytes(&bytes_first, &bytes_current);
                    let normalized_hamming =
                        hamming as f64 / (keysize as f64 * (max_chunk_bytes - 1) as f64);
                    normalized_hamming
                })
                .sum();
            // let sum_hamming = hamming_1 + hamming_2;
            (keysize, hamming_candidate)
        })
        .collect();
    vec_hamming_with_size
        .into_iter()
        .min_by(|t1, t2| t1.1.total_cmp(&t2.1))
        .unwrap()
        .0
}

fn c_str_to_bytes(c_str: &str) -> Vec<u8> {
    c_str.chars().map(|c| c as u8).collect()
}

fn hamming_distance_bytes(bytes_first: &[u8], bytes_second: &[u8]) -> u32 {
    bytes_first
        .into_iter()
        .zip(bytes_second.into_iter())
        .map(|(b1, b2)| {
            (0..8)
                .map(|bit_num| {
                    let bit_b1 = (b1 >> bit_num) & 1;
                    let bit_b2 = (b2 >> bit_num) & 1;
                    if bit_b1 == bit_b2 {
                        0
                    } else {
                        1
                    }
                })
                .sum::<u32>()
        })
        .sum()
}
fn hamming_distance(first: &str, second: &str) -> u32 {
    let bytes_first = c_str_to_bytes(first);
    let bytes_second = c_str_to_bytes(second);
    hamming_distance_bytes(&bytes_first, &bytes_second)
}

fn encrypt_message_repeating_xor(message: &Vec<u8>, key: &str) -> Vec<u8> {
    message
        .into_iter()
        .zip(key.chars().cycle())
        .map(|(c, char_key)| {
            let byte_c = *c;
            let byte_key = char_key as u8;
            byte_c ^ byte_key
        })
        .collect()
}

fn get_min_message_decode(test_string: &str, char_freq: &HashMap<char, f64>) -> (String, f64, u8) {
    let message_and_scores: Vec<_> = (0..=255)
        .map(|byte_key| {
            let key_repeat = std::iter::repeat(byte_key)
                .take(test_string.len() / 2)
                .collect();
            let test_bytes = hex_string_to_byte_vec(test_string);
            let bytes_decoded = fixed_xor(test_bytes, key_repeat);
            let message: String = bytes_decoded.into_iter().map(|b| b as char).collect();
            let score = score_string(&message, &char_freq);
            (message, score, byte_key)
        })
        .collect();
    message_and_scores
        .into_iter()
        .min_by(|t1, t2| t1.1.total_cmp(&t2.1))
        .unwrap()
}

fn hex_to_b64(hex: &str) -> String {
    let bytes = hex_string_to_byte_vec(hex);
    bytes
        .chunks(3)
        .flat_map(|chunk| {
            let mut num: u32 = 0;
            let mut current;
            for index in 0..=2 {
                current = chunk[index] as u32;
                num += current << ((16 - index * 8) as u32);
            }
            // we have 24 bits filled
            // now we convert them 6 bits at a time
            let mask_6_bits = 2u32.pow(6u32) - 1u32;
            let mut string_results = String::from("");
            for index in 0..=3 {
                let truncated = num >> (6u32 * (3u32 - index));
                let value_6bit = (truncated & mask_6_bits) as u8;
                let value_char = convert_6_bits_to_letter(value_6bit);
                string_results.push(value_char);
            }
            string_results.chars().collect::<Vec<_>>().into_iter()
        })
        .collect()
}

fn b64_to_bytes(b64: &str) -> Vec<u8> {
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

fn hex_string_to_byte_vec(hex: &str) -> Vec<u8> {
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

fn byte_vec_to_hex_chars(bytes: Vec<u8>) -> String {
    bytes
        .into_iter()
        .flat_map(|byte| {
            let (c1, c2) = convert_u8_to_hex_tuple(byte);
            [c1, c2].into_iter()
        })
        .collect()
}

fn fixed_xor(bytes_1: Vec<u8>, bytes_2: Vec<u8>) -> Vec<u8> {
    bytes_1
        .into_iter()
        .zip(bytes_2.into_iter())
        .map(|(b1, b2)| b1 ^ b2)
        .collect()
}

fn fixed_xor_hex(hex1: &str, hex2: &str) -> String {
    let bytes_1 = hex_string_to_byte_vec(hex1);
    let bytes_2 = hex_string_to_byte_vec(hex2);
    let vec_xor = fixed_xor(bytes_1, bytes_2);
    byte_vec_to_hex_chars(vec_xor)
}

fn convert_u8_to_hex_char(char_num: u8) -> char {
    let c = match char_num {
        0..=9 => ('0' as u8 + char_num) as char,
        10..=15 => ('a' as u8 + (char_num - 10)) as char,
        _ => panic!("Input num not in range"),
    };
    c
}

fn convert_u8_to_hex_tuple(byte: u8) -> (char, char) {
    let mask = 2u8.pow(4) - 1;
    let c1_num = byte & mask;
    let c2_num = byte >> 4;
    let c1 = convert_u8_to_hex_char(c1_num);
    let c2 = convert_u8_to_hex_char(c2_num);
    (c2, c1)
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

fn convert_6_bits_to_letter(value: u8) -> char {
    let char_num = match value {
        0..=25 => 'A' as u8 + value,
        26..=51 => 'a' as u8 + value - 26,
        52..=61 => '0' as u8 + value - 52,
        62 => '+' as u8,
        63 => '/' as u8,
        _ => panic!("input 6 bit value invalid"),
    };
    char_num as char
}

fn instanciate_hash_frequency() -> HashMap<char, f64> {
    let mut hashmap = HashMap::new();
    hashmap.insert('e', 0.1);
    hashmap.insert('a', 0.085);
    // hashmap.insert('r', 0.075);
    // hashmap.insert('i', 0.075);
    // hashmap.insert('t', 0.09);
    // hashmap.insert('o', 0.07);
    // hashmap.insert('n', 0.06);
    hashmap.insert(' ', 0.16);
    hashmap
}

fn get_score_freq(computed_freq: Option<f64>, reference_freq: f64) -> f64 {
    if let Some(freq) = computed_freq {
        (freq - reference_freq).abs()
    } else {
        0f64
    }
}
fn score_string(decoded: &str, char_freq: &HashMap<char, f64>) -> f64 {
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
fn ex1() {
    let hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    // let hex = "49276d";
    let b64_encoding = hex_to_b64(&hex);
    dbg!(b64_encoding);
}
fn ex2() {
    let hex1 = "1c0111001f010100061a024b53535009181c".to_string();
    let hex2 = "686974207468652062756c6c277320657965".to_string();
    let xor_str = fixed_xor_hex(&hex1, &hex2);
    dbg!(xor_str);
}
fn ex4() {
    let char_freq = instanciate_hash_frequency();
    let file_contents = fs::read_to_string("data/set_of_potential_xor.txt").unwrap();
    let min_all = file_contents
        .trim_matches('\n')
        .split("\n")
        .map(|test_string| {
            let min_msg = get_min_message_decode(test_string, &char_freq);
            min_msg
        })
        .min_by(|t1, t2| t1.1.total_cmp(&t2.1))
        .unwrap();
    dbg!(min_all);
}
fn ex5() {
    let message =
        "Burning 'em, if you ain't quick and nimble I go crazy when I hear a cymbal".to_string();
    let key = "ICE".to_string();
    let message_bytes: Vec<u8> = c_str_to_bytes(&message);
    let bytes_encrypted = encrypt_message_repeating_xor(&message_bytes, &key);
    let hex_encrypted = byte_vec_to_hex_chars(bytes_encrypted.clone());
    dbg!(hex_encrypted);
}
fn ex6() {
    let hamming_test = hamming_distance("this is a test", "wokka wokka!!!");
    dbg!(hamming_test);
    // // 3
    let file_contents = fs::read_to_string("data/encrypted_message_repeating_xor.txt").unwrap();
    let contents = &file_contents.replace("\n", "");
    let bytes = b64_to_bytes(&contents);
    let results = decrypt_repeating_xor(&bytes);
    dbg!(results);
}
fn ex7() {
    let key_string = "YELLOW SUBMARINE".to_string();
    let key = c_str_to_bytes(&key_string);
    let file_contents = fs::read_to_string("data/encrypted_ECB_AES-128.txt").unwrap();
    let contents = &file_contents.replace("\n", "");
    let bytes = b64_to_bytes(&contents);
    let cipher = Cipher::aes_128_ecb();
    let mut ctx = CipherCtx::new().unwrap();
    ctx.decrypt_init(Some(cipher), Some(&key), None).unwrap();
    let mut plaintext = vec![];
    ctx.cipher_update_vec(&bytes, &mut plaintext).unwrap();
    ctx.cipher_final_vec(&mut plaintext).unwrap();
    let message: String = plaintext.into_iter().map(|b| b as char).collect();
    dbg!(message);
}

fn ex8() {
    let file_contents = fs::read_to_string("data/encrypted_ecb_candidates.txt").unwrap();
    let min_all = file_contents
        .trim_matches('\n')
        .split("\n")
        .enumerate()
        .map(|(index, test_string)| {
            // we count the number of redundancies between blocks of 16 bytes
            let bytes_candidates = hex_string_to_byte_vec(test_string);
            let sum_hammings: u32 = bytes_candidates
                .windows(32)
                .step_by(16)
                .map(|slice| {
                    let set_1 = &slice[0..16];
                    let set_2 = &slice[16..32];
                    let hamming = hamming_distance_bytes(set_1, set_2);
                    hamming
                })
                .sum();
            dbg!(sum_hammings);
            (index, sum_hammings)
        })
        .min_by(|t1, t2| t1.1.cmp(&t2.1))
        .unwrap();
    dbg!(min_all);
}
