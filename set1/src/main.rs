use std::collections::HashMap;
use std::fs;
use std::iter::once;

fn main() {
    // let hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    // let hex = "49276d";
    // let b64_encoding = hex_to_b64(&hex);
    // dbg!(b64_encoding);
    // let hex1 = "1c0111001f010100061a024b53535009181c".to_string();
    // let hex2 = "686974207468652062756c6c277320657965".to_string();
    // let xor_str = fixed_xor(&hex1, &hex2);
    // dbg!(xor_str);
    // ex 4
    // let file_contents = fs::read_to_string("data/set_of_potential_xor.txt").unwrap();
    // let char_freq = instanciate_hash_frequency();
    // let min_all = file_contents
    //     .split("\n")
    //     .map(|test_string| get_min_message_decode(test_string, &char_freq))
    //     .min_by(|t1, t2| t1.1.total_cmp(&t2.1))
    //     .unwrap();
    // dbg!(min_all);
    // ex 5
    // let message =
    //     "Burning 'em, if you ain't quick and nimble I go crazy when I hear a cymbal".to_string();
    // let key = "ICE".to_string();
    // let bytes_encrypted = encrypt_message_repeating_xor(&message, &key);
    // let hex_encrypted = byte_vec_to_hex_chars(bytes_encrypted);
    // dbg!(hex_encrypted);
    // ex 6
    // 2: hamming distance
    let hamming_test = hamming_distance("this is a test", "wokka wokka!!!");
    dbg!(hamming_test);
    // 3
    let file_contents = fs::read_to_string("data/encrypted_message_repeating_xor.txt").unwrap();
    let bytes = b64_to_bytes(&file_contents.replace("\n", ""));
    let vec_hamming_with_size: Vec<_> = (1..40)
        .map(|keysize| {
            let mut iter_bytes = bytes.iter();
            let mut_ref_iter = iter_bytes.by_ref();
            let bytes_first: Vec<u8> = mut_ref_iter.take(keysize).cloned().collect();
            let bytes_second: Vec<u8> = mut_ref_iter.take(keysize).cloned().collect();
            let bytes_third: Vec<u8> = mut_ref_iter.take(keysize).cloned().collect();
            let bytes_forth: Vec<u8> = mut_ref_iter.take(keysize).cloned().collect();
            // dbg!(bytes_first.clone());
            // dbg!(bytes_second.clone());
            let hamming_1 = hamming_distance_bytes(&bytes_first, &bytes_second);
            let hamming_2 = hamming_distance_bytes(&bytes_second, &bytes_third);
            let hamming_3 = hamming_distance_bytes(&bytes_third, &bytes_forth);
            let hamming_4 = hamming_distance_bytes(&bytes_first, &bytes_forth);
            let normalized_hamming_1 = hamming_1 as f64 / keysize as f64;
            let normalized_hamming_2 = hamming_2 as f64 / keysize as f64;
            let normalized_hamming_3 = hamming_3 as f64 / keysize as f64;
            let normalized_hamming_4 = hamming_4 as f64 / keysize as f64;
            let normalized_hamming = normalized_hamming_1
                + normalized_hamming_2
                + normalized_hamming_3
                + normalized_hamming_4;
            dbg!(normalized_hamming);
            (keysize, normalized_hamming)
        })
        .collect();

    let min_hamming = vec_hamming_with_size
        .into_iter()
        .min_by(|t1, t2| t1.1.total_cmp(&t2.1))
        .unwrap();
    // dbg!(min_hamming);
    let keysize_candidate = min_hamming.0;
}

fn c_str_to_bytes(c_str: &str) -> Vec<u8> {
    c_str.chars().map(|c| c as u8).collect()
}

fn hamming_distance_bytes(bytes_first: &Vec<u8>, bytes_second: &Vec<u8>) -> u32 {
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

fn encrypt_message_repeating_xor(message: &str, key: &str) -> Vec<u8> {
    message
        .chars()
        .zip(key.chars().cycle())
        .map(|(c, char_key)| {
            let byte_c = c as u8;
            let byte_key = char_key as u8;
            byte_c ^ byte_key
        })
        .collect()
}

fn get_min_message_decode(test_string: &str, char_freq: &HashMap<char, f64>) -> (String, f64, u8) {
    let message_and_scores: Vec<_> = (0..=255)
        .map(|byte_key| {
            let (c1, c2) = convert_u8_to_hex_tuple(byte_key);
            let hex_str_decode: String = once(c1)
                .chain(once(c2))
                .cycle()
                .take(test_string.len())
                .collect();
            // dbg!(hex_str_decode.clone());
            let decoded_hex = fixed_xor(&test_string, &hex_str_decode);
            let bytes_decoded = hex_string_to_byte_vec(&decoded_hex);
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
    let bytes: Vec<u32> = hex
        .chars()
        .map(|c| convert_hex_char_to_u8(c) as u32)
        .collect();
    let b64: String = bytes
        .chunks(6)
        .flat_map(|chunk| {
            let mut num = 0;
            let mut current;
            for index in 0..=5 {
                current = chunk.get(index).cloned().unwrap_or(0);
                num += current << ((20 - index * 4) as u32);
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
        .collect();
    b64
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
            let bytes: Vec<_> = (0..=cur_num_bytes_decode)
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
    dbg!(letter.clone());
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

fn fixed_xor(hex1: &str, hex2: &str) -> String {
    let bytes_1 = hex_string_to_byte_vec(hex1);
    let bytes_2 = hex_string_to_byte_vec(hex2);
    let vec_xor: Vec<_> = bytes_1
        .into_iter()
        .zip(bytes_2.into_iter())
        .map(|(b1, b2)| b1 ^ b2)
        .collect();
    // dbg!(vec_xor.clone());
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
    hashmap.insert('e', 0.111);
    hashmap.insert('a', 0.085);
    hashmap.insert('r', 0.075);
    hashmap.insert('i', 0.075);
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
    score
}
