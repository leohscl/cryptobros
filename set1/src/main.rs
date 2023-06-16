use std::collections::HashMap;

fn main() {
    // let hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    let hex = "49276d";
    let b64_encoding = hex_to_b64(&hex);
    dbg!(b64_encoding);
    let hex1 = "1c0111001f010100061a024b53535009181c".to_string();
    let hex2 = "686974207468652062756c6c277320657965".to_string();
    let xor_str = fixed_xor(hex1, hex2);
    dbg!(xor_str);
    let char_freq = instanciate_hash_frequency();
    let test_string =
        "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736".to_string();
    for char_num in 0..16 {
        let hex = convert_u8_to_hex_char(char_num);
        let score = score_hex_char_decoding(&test_string, hex, &char_freq);
        println!("hex {} has a score of {}", hex, score);
    }
}

fn instanciate_hash_frequency() -> HashMap<char, f64> {
    let mut hashmap = HashMap::new();
    hashmap.insert('e', 11.1);
    hashmap.insert('a', 8.5);
    hashmap.insert('r', 7.5);
    hashmap.insert('i', 7.5);
    hashmap
}

// the larger the score, the worst
fn score_hex_char_decoding(hex: &String, c: u8, char_freq: &HashMap<char, f64>) -> f64 {
    let vec_c: Vec<char> = hex.chars().collect();
    let vec_bytes: Vec<_> = vec_c
        .chunks(2)
        .into_iter()
        .map(|chunk| {
            let pair = (chunk[0], chunk[1]);
            convert_hex_tuple_to_u8(pair)
        })
        .collect();
    let decoded_vec: Vec<_> = vec_bytes.into_iter().map(|b1| b1 ^ c).collect();
    let decoded = bytes_to_b64(&xor_c);
    dbg!(decoded.clone());
    let length = decoded.len() as f64;
    let mut score = 0f64;
    for c_test in char_freq.keys() {
        let sum_decode = decoded
            .chars()
            .map(|c| if c == *c_test { 1 } else { 0 })
            .sum::<u32>();
        let freq = sum_decode as f64 / length;
        let score_letter = get_score_freq(char_freq.get(c_test).cloned(), freq);
        score += score_letter;
    }
    score
}

fn get_score_freq(computed_freq: Option<f64>, reference_freq: f64) -> f64 {
    if let Some(freq) = computed_freq {
        (freq - reference_freq).abs()
    } else {
        0f64
    }
}

fn bytes_to_b64(hex: &Vec<u8>) -> String {
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
fn xor_bytes(hex1: &Vec<u8>, c: u8) -> String {}

fn fixed_xor(hex1: String, hex2: String) -> String {
    let bytes_1: Vec<u8> = hex1.chars().map(|c| convert_hex_char_to_u8(c)).collect();
    let bytes_2: Vec<u8> = hex2.chars().map(|c| convert_hex_char_to_u8(c)).collect();
    let vec_xor: Vec<_> = bytes_1
        .into_iter()
        .zip(bytes_2.into_iter())
        .map(|(b1, b2)| b1 ^ b2)
        .collect();
    vec_xor
        .into_iter()
        .map(|byte| convert_u8_to_hex_char(byte))
        .collect::<String>()
}

fn convert_u8_to_hex_char(char_num: u8) -> char {
    let c = match char_num {
        0..=9 => ('0' as u8 + char_num) as char,
        10..=15 => ('a' as u8 + (char_num - 10)) as char,
        _ => panic!("Input num not in range"),
    };
    c
}
fn convert_hex_tuple_to_u8(tuple_hex: (char, char)) -> u8 {
    let first_4_bit = convert_hex_char_to_u8(tuple_hex.0);
    let last_4_bit = convert_hex_char_to_u8(tuple_hex.1);
    first_4_bit << 4u8 + last_4_bit
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
        63 => '\\' as u8,
        _ => panic!("input 6 bit value invalid"),
    };
    char_num as char
}

// 49276d
// 0100 1001 0010 0111 0110 1101
// 010010 010010 011101 101101
// 18 18 29 45
