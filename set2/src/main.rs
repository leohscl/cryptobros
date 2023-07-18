mod utils;
use rand::Rng;
use std::collections::HashMap;
use std::fs;
use utils::b64_to_bytes;
use utils::bytes_as_string;
use utils::c_str_to_bytes;
use utils::count_repeating_bytes;
use utils::decrypt_cbc;
use utils::decrypt_ecb;
use utils::encrypt_ecb;
use utils::fixed_xor;
use utils::get_consecutive_repeat_index;
// use utils::has_repeating_bytes;

static mut KEY: Vec<u8> = Vec::new();
static mut RANDOM_BYTES: Vec<u8> = Vec::new();
static UNKNOWN_B64: &str = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg\
                        aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq\
                        dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg\
                        YnkK";

#[derive(Debug)]
struct PkcsError;

fn main() {
    let random_key = generate_aes_key();
    unsafe {
        KEY = random_key;
    }
    let mut rng = rand::thread_rng();
    let size_prepend = rng.gen_range(1..=100) as usize;
    let mut prepend_random = Vec::with_capacity(size_prepend);
    for _ in 0..size_prepend {
        let rand_byte: u8 = rng.gen();
        prepend_random.push(rand_byte);
    }
    unsafe {
        RANDOM_BYTES = prepend_random;
    }
    ex9();
    ex10();
    ex11();
    ex12();
    ex13();
    ex14();
    ex15();
    ex16();
}

fn ex16() {
    let test_str_1 = "Hello everybody tout le monde";
    let encoded_test_1 = encode_cbc_with_prepend_and_append(test_str_1);
    assert!(!decode_cbc_find_admin(&encoded_test_1));
    let test_str_2 = "Hello ! ;admin=true;Everything looks okay here !";
    let encoded_test_2 = encode_cbc_with_prepend_and_append(test_str_2);
    assert!(!decode_cbc_find_admin(&encoded_test_2));
    let test_admin_true = "test=hello;admin=true;hello=test";
    let key;
    unsafe {
        key = KEY.clone();
    }
    let mut test_admin_bytes = c_str_to_bytes(test_admin_true);
    pcks7_padding(&mut test_admin_bytes, 16);
    let admin_encrypted = encrypt_cbc(&test_admin_bytes, &key, &vec![0u8; 16]);
    assert!(decode_cbc_find_admin(&admin_encrypted));
    let admin_cbc_encoded = create_admin_cbc();
    let has_admin = decode_cbc_find_admin(&admin_cbc_encoded);
    assert!(has_admin);
}

fn create_admin_cbc() -> Vec<u8> {
    let prepend = "comment1=cooking%20MCs;userdata=";
    let append = ";comment2=%20like%20a%20pound%20of%20bacon";
    let string_no_input = format!("{}{}", prepend, append);
    let block_size = 16;
    let start_of_bitflip = prepend.len() - (prepend.len() % block_size) - block_size;
    let start_target_bitflip = start_of_bitflip + block_size;
    let initial_plain = &string_no_input[start_target_bitflip..(start_target_bitflip + block_size)];
    dbg!(&initial_plain);
    let initial_bytes = c_str_to_bytes(initial_plain);
    let target = c_str_to_bytes(";admin=true;aaaa");
    let byte_add_to_get_admin = get_byte_distance(&target, &initial_bytes);

    // work on encrypted
    let mut encryption = encode_cbc_with_prepend_and_append("");
    let bitflip_block = &mut encryption[start_of_bitflip..(start_of_bitflip + block_size)];
    bitflip_block
        .iter_mut()
        .zip(byte_add_to_get_admin.into_iter())
        .for_each(|(byte_initial, byte_to_add)| *byte_initial = *byte_initial ^ byte_to_add);
    encryption
}

fn get_byte_distance(target: &[u8], current: &[u8]) -> Vec<u8> {
    assert!(target.len() == current.len());
    // dbg!(&target);
    target
        .into_iter()
        .zip(current.into_iter())
        .map(|(target, current)| target ^ *current)
        .collect()
}

fn decode_cbc_find_admin(input_bytes: &[u8]) -> bool {
    let key;
    unsafe {
        key = KEY.clone();
    }
    let bytes_decoded = decrypt_cbc(input_bytes, &key, &vec![0u8; 16]);
    let string_decoded = bytes_as_string(&pkcs_validation(&bytes_decoded).unwrap());
    dbg!(&string_decoded);
    string_decoded
        .split(';')
        .any(|substr| substr == "admin=true")
}

fn encode_cbc_with_prepend_and_append(input_string: &str) -> Vec<u8> {
    let key;
    unsafe {
        key = KEY.clone();
    }
    let prepend = "comment1=cooking%20MCs;userdata=";
    let append = ";comment2=%20like%20a%20pound%20of%20bacon";
    let quoted_input = quote_out_special_chars(input_string);
    // dbg!(&quoted_input);
    let string_to_encrypt = format!("{}{}{}", prepend, quoted_input, append);
    // dbg!(&string_to_encrypt);
    let mut bytes_input = c_str_to_bytes(&string_to_encrypt);
    pcks7_padding(&mut bytes_input, 16);
    encrypt_cbc(&bytes_input, &key, &vec![0u8; 16])
}

fn quote_out_special_chars(input: &str) -> String {
    let special_chars = [';', '='];
    let results = input
        .chars()
        .flat_map(|c| match special_chars.contains(&c) {
            false => Box::new(std::iter::once(c)) as Box<dyn Iterator<Item = char>>,
            true => Box::new(
                std::iter::once('\"')
                    .chain(std::iter::once(c))
                    .chain(std::iter::once('\"')),
            ),
        })
        .collect();
    results
}

fn ex15() {
    let test_1 = c_str_to_bytes("ICE ICE BABY\x04\x04\x04\x04");
    let conversion_1 = pkcs_validation(&test_1);
    assert!(conversion_1.is_ok());
    dbg!(&conversion_1.map(|vec| bytes_as_string(&vec)));
    let test_2 = c_str_to_bytes("ICE ICE BABY\x05\x05\x05\x05");
    let conversion_2 = pkcs_validation(&test_2);
    assert!(conversion_2.is_err());
    let test_3 = c_str_to_bytes("ICE ICE BABY\x01\x02\x03\x04");
    let conversion_3 = pkcs_validation(&test_3);
    assert!(conversion_3.is_err());
}

fn pkcs_validation(padded: &[u8]) -> Result<Vec<u8>, PkcsError> {
    let len = padded.len();
    let last = padded.iter().last().ok_or(PkcsError {})?;
    let num_padding = *last as usize;
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
fn ex14() {
    let plain_bytes = decipher_with_prefix_oracle();
    dbg!(bytes_as_string(&plain_bytes));
}
fn ex13() {
    let test_string = "foo=bar&baz=qux&zap=zazzle";
    let map_test = k_b_parsing(test_string).unwrap();
    let decoded_test = profile_as_k_b(&map_test);
    dbg!(decoded_test);
    // let profile_kb = profile_for("foo@bar.com");
    // dbg!(&profile_kb);
    let admin_profile = make_admin_profile();
    let decoded_admin = decrypt_user_profile(&admin_profile);
    let admin_str = bytes_as_string(&decoded_admin);
    dbg!(&admin_str);
}

fn encrypt_profile(email: &str) -> Vec<u8> {
    let profile_kb = profile_for(&email);
    // dbg!(&map_profile);
    // let profile_kb = profile_as_k_b(&map_profile);
    // dbg!(&profile_kb);
    let plain_bytes = c_str_to_bytes(&profile_kb);
    // dbg!(&plain_bytes);
    let encrypted = encrypt_user_profile(&plain_bytes);
    encrypted
}

fn make_admin_profile() -> Vec<u8> {
    // "email=aaaaa@bar.com&uid=10&role=user"
    //  12345678123456781234567812345678
    // get first part of result
    let email_part_1 = "aaaaa@bar.com";
    let bytes_email_p1 = encrypt_profile(email_part_1);
    assert_eq!(bytes_email_p1.len(), 48);
    let bytes_1: Vec<u8> = bytes_email_p1.into_iter().take(32).collect();

    // "email=aaaaaaaaa@adminUUUUUUUUUUU&uid=10&role=user"
    //  12345678123456781234567812345678
    //  email=aaaaaaaaa@adminTTTTTTTTTTT
    // get second part of result
    let mut email_start_bytes = c_str_to_bytes("aaaaaaaaa@admin");
    let email_padding_bytes = std::iter::repeat(11u8).take(11);
    email_start_bytes.extend(email_padding_bytes);
    assert_eq!(email_start_bytes.len(), 26);
    let encrypted_email_bytes = encrypt_profile(&bytes_as_string(&email_start_bytes));
    let bytes_admin = encrypted_email_bytes.into_iter().skip(16).take(16);
    let mut bytes_full = bytes_1.clone();
    bytes_full.extend(bytes_admin);
    bytes_full
}

fn encrypt_user_profile(profile: &[u8]) -> Vec<u8> {
    let key;
    unsafe {
        key = KEY.clone();
    }
    encrypt_ecb(profile, &key)
}

fn decrypt_user_profile(profile_encoded: &[u8]) -> Vec<u8> {
    let key;
    unsafe {
        key = KEY.clone();
    }
    decrypt_ecb(profile_encoded, &key)
}

fn profile_for(email: &str) -> String {
    let no_meta_email: String = email.chars().filter(|&c| c != '&' && c != '=').collect();
    let encoded_str = format!("email={}&uid=10&role=user", no_meta_email);
    // bg!(&encoded_str);
    // k_b_parsing(&encoded_str).expect("Parsing should not fail here")
    encoded_str
}

fn profile_as_k_b(map: &HashMap<String, String>) -> String {
    let vec_res: Vec<String> = map
        .into_iter()
        .map(|(key, value)| {
            let mut return_str = key.to_string();
            return_str.extend(std::iter::once('=').chain(value.chars()));
            return_str
        })
        .collect();
    vec_res.join("&")
}

fn k_b_parsing(input: &str) -> Result<HashMap<String, String>, ()> {
    input
        .split('&')
        .map(|substr| {
            let mut iterate_eq = substr.split('=');
            let first = iterate_eq.next().ok_or(())?;
            let second = iterate_eq.next().ok_or(())?;
            Ok((first.to_string(), second.to_string()))
        })
        .collect()
}
fn decipher_with_prefix_oracle() -> Vec<u8> {
    let block_size = get_block_size_bytes_random();
    dbg!(block_size);
    assert!(block_size >= 2);

    let repeated_bytes: Vec<u8> = std::iter::repeat(0u8).take(block_size * 4).collect();
    let encode_repetition = encryption_oracle_ecb(&repeated_bytes);
    let is_ecb = count_repeating_bytes(encode_repetition) >= 1;

    // start with the index of the repeated bytes
    let (index_end_repetition, bytes_complete) = get_whole_block_prefix(block_size);
    dbg!(&index_end_repetition);
    // dbg!(&bytes_complete);

    let message_to_decrypt_len = encryption_oracle_random_bytes_ecb(&bytes_complete).len();

    // let mut decoded_bytes = vec![];
    let mut decoded_bytes = vec![0u8; block_size];

    let mut count = 1;
    let num_remainder_target_string = loop {
        let prepend: Vec<_> = bytes_complete
            .iter()
            .cloned()
            .chain(std::iter::repeat(0u8).take(count))
            .collect();
        let new_length = encryption_oracle_random_bytes_ecb(&prepend).len();
        if message_to_decrypt_len != new_length {
            break count;
        }
        count += 1;
    };

    if is_ecb {
        while (decoded_bytes.len() + index_end_repetition)
            != (message_to_decrypt_len + num_remainder_target_string)
        {
            // will be used
            let short_1_byte: Vec<u8> = decoded_bytes
                .clone()
                .into_iter()
                .rev()
                .take(block_size - 1)
                .rev()
                .collect();

            let mut all_potential_encoding = HashMap::new();
            // check all potential hash
            for potential_byte in 0..255 {
                let plain_test: Vec<_> = short_1_byte
                    .iter()
                    .cloned()
                    .chain(std::iter::once(potential_byte))
                    .collect();
                let mut new_candidate_with_bytes_complete = bytes_complete.clone();
                new_candidate_with_bytes_complete.extend_from_slice(&plain_test);
                let potential_encoding =
                    encryption_oracle_random_bytes_ecb(&new_candidate_with_bytes_complete);
                let first_block_plain: Vec<_> = plain_test.clone();
                let first_block_encoded: Vec<_> = potential_encoding
                    .into_iter()
                    .skip(index_end_repetition)
                    .take(block_size)
                    .collect();
                all_potential_encoding.insert(first_block_encoded, first_block_plain);
            }
            let length_decoded_needed = decoded_bytes.len() % block_size;
            // dbg!(&length_decoded_needed);
            let garbage_append: Vec<_> = std::iter::repeat(0u8)
                .take(block_size - 1 - length_decoded_needed)
                .collect();
            let mut padded_bytes_with_garbage = bytes_complete.clone();
            padded_bytes_with_garbage.extend(garbage_append);
            let num_skip =
                index_end_repetition + decoded_bytes.len() - length_decoded_needed - block_size;
            // dbg!(num_skip);
            let encode_right_number_hidden =
                encryption_oracle_random_bytes_ecb(&padded_bytes_with_garbage);
            let encoded_block_of_interest: Vec<_> = encode_right_number_hidden
                .into_iter()
                .skip(num_skip)
                .take(block_size)
                .collect();

            let first_block_plain_1_byte_hidden = all_potential_encoding
                .get(&encoded_block_of_interest)
                .unwrap();
            let plain_byte = first_block_plain_1_byte_hidden.last().unwrap();
            decoded_bytes.push(*plain_byte);
            // dbg!(&plain_byte);
        }
    } else {
        panic!("Not ecb !");
    }
    decoded_bytes.into_iter().skip(block_size).collect()
}

fn get_whole_block_prefix(block_size: usize) -> (usize, Vec<u8>) {
    let base_encoding = encryption_oracle_random_bytes_ecb(&vec![]);
    let base_repetition_opt_index = get_consecutive_repeat_index(base_encoding, block_size);
    // add gradually until we get a new repetition
    let mut count = 1;
    let (index_end_repetition, bytes_complete) = loop {
        let prepend: Vec<_> = std::iter::repeat(0u8).take(count).collect();
        let encoding_with_new_repeat = encryption_oracle_random_bytes_ecb(&prepend);
        let potential_new_repeat_index =
            get_consecutive_repeat_index(encoding_with_new_repeat, block_size);
        if potential_new_repeat_index != base_repetition_opt_index {
            break (potential_new_repeat_index.unwrap(), prepend);
        }
        count += 1;
    };
    (index_end_repetition, bytes_complete)
}
fn get_block_size_bytes_random() -> usize {
    let encryption_base_size = encryption_oracle_random_bytes_ecb(&vec![]).len();
    let mut encryption_next_size;
    let mut count = 1;
    let reminder_and_size = loop {
        let prepend: Vec<_> = std::iter::repeat(0u8).take(count).collect();
        encryption_next_size = encryption_oracle_random_bytes_ecb(&prepend).len();
        if encryption_base_size != encryption_next_size {
            break (encryption_next_size - encryption_base_size);
        }
        count += 1;
    };
    reminder_and_size
}

fn decipher_using_oracle() -> Vec<u8> {
    let (reminder, block_size) = get_block_size_bytes_and_reminder();
    // dbg!(block_size);
    let repeated_bytes: Vec<u8> = std::iter::repeat(0u8).take(block_size * 4).collect();
    let encode_repetition = encryption_oracle_ecb(&repeated_bytes);
    let is_ecb = count_repeating_bytes(encode_repetition) >= 1;
    let message_to_decrypt = encryption_oracle_ecb(&vec![]);
    // dbg!(is_ecb);
    let mut decoded_bytes = vec![0u8; block_size];
    assert!(block_size >= 2);

    // let num_block_decipher = message_to_decrypt.len() / block_size;
    if is_ecb {
        while decoded_bytes.len() != (message_to_decrypt.len() + reminder) {
            // will be used
            let short_1_byte: Vec<u8> = decoded_bytes
                .clone()
                .into_iter()
                .rev()
                .take(block_size - 1)
                .rev()
                .collect();
            // dbg!(&short_1_byte);

            let mut all_potential_encoding = HashMap::new();
            // check all potential hash
            for potential_byte in 0..255 {
                let plain_test: Vec<_> = short_1_byte
                    .iter()
                    .cloned()
                    .chain(std::iter::once(potential_byte))
                    .collect();
                let potential_encoding = encryption_oracle_ecb(&plain_test);
                let first_block_plain: Vec<_> = plain_test.into_iter().take(block_size).collect();
                let first_block_encoded: Vec<_> =
                    potential_encoding.into_iter().take(block_size).collect();
                all_potential_encoding.insert(first_block_encoded, first_block_plain);
            }
            let length_decoded_needed = decoded_bytes.len() % block_size;
            let garbage_append: Vec<_> = std::iter::repeat(0u8)
                .take(block_size - 1 - length_decoded_needed)
                .collect();

            let num_skip = decoded_bytes.len() - length_decoded_needed - block_size;
            // dbg!(decoded_bytes.len());
            // dbg!(num_skip);
            let encode_right_number_hidden = encryption_oracle_ecb(&garbage_append);
            let encoded_block_of_interest: Vec<_> = encode_right_number_hidden
                .into_iter()
                .skip(num_skip)
                .take(block_size)
                .collect();

            let first_block_plain_1_byte_hidden = all_potential_encoding
                .get(&encoded_block_of_interest)
                .unwrap();
            let plain_byte = first_block_plain_1_byte_hidden.last().unwrap();
            decoded_bytes.push(*plain_byte);
        }
    } else {
        panic!("Not ecb !");
    }
    decoded_bytes.into_iter().skip(block_size).collect()
}

fn get_block_size_bytes_and_reminder() -> (usize, usize) {
    let encryption_base_size = encryption_oracle_ecb(&vec![]).len();
    let mut encryption_next_size;
    let mut count = 1;
    let reminder_and_size = loop {
        let prepend: Vec<_> = std::iter::repeat(0u8).take(count).collect();
        encryption_next_size = encryption_oracle_ecb(&prepend).len();
        if encryption_base_size != encryption_next_size {
            break (count, (encryption_next_size - encryption_base_size));
        }
        count += 1;
    };
    reminder_and_size
}

fn encryption_oracle_ecb(prepend_text: &[u8]) -> Vec<u8> {
    let plain_bytes = b64_to_bytes(UNKNOWN_B64);
    let unknown_key;
    unsafe {
        unknown_key = KEY.clone();
    }
    let to_encrypt: Vec<_> = prepend_text
        .into_iter()
        .chain(plain_bytes.iter())
        .cloned()
        .collect();
    encrypt_ecb(&to_encrypt, &unknown_key)
}

fn encryption_oracle_random_bytes_ecb(prepend_text: &[u8]) -> Vec<u8> {
    let prepend_random;
    unsafe {
        prepend_random = RANDOM_BYTES.clone();
    }
    let unknown_key;
    unsafe {
        unknown_key = KEY.clone();
    }
    let plain_bytes = b64_to_bytes(UNKNOWN_B64);
    let to_encrypt: Vec<_> = prepend_random
        .into_iter()
        .chain(prepend_text.into_iter().cloned())
        .chain(plain_bytes.into_iter())
        .collect();
    encrypt_ecb(&to_encrypt, &unknown_key)
}

fn ex12() {
    let plain_bytes = decipher_using_oracle();
    dbg!(bytes_as_string(&plain_bytes));
}

fn ex11() {
    let message = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string();
    let bytes_msg = c_str_to_bytes(&message);
    for _ in 0..10 {
        let (ecb_used, encrypted) = encryption_oracle(bytes_msg.clone());
        let repeating_bytes = count_repeating_bytes(encrypted) >= 1;
        assert!(ecb_used == repeating_bytes);
    }
}

fn generate_5_10_bytes() -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let number = rng.gen_range(5..=10) as usize;
    let mut bytes = Vec::new();
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
