mod utils;

use sha1::Digest;
use sha1::Sha1;
use utils::b64_to_bytes;
use utils::bytes_as_string;
use utils::c_str_to_bytes;
use utils::decrypt_cbc;
use utils::encrypt_cbc;
use utils::encrypt_ecb;
use utils::fixed_xor;
use utils::generate_aes_key;
use utils::pkcs_validation;

use openssl::cipher::Cipher;
use openssl::cipher_ctx::CipherCtx;

static mut KEY: Vec<u8> = Vec::new();

fn main() {
    let random_key = generate_aes_key();
    unsafe {
        KEY = random_key;
    }
    ex25();
    ex26();
    ex27();
    ex28();
    ex29();
}

fn ex29() {
    let message = b"test";
    let padding = find_md_padding(message);
    dbg!(padding);
}

fn find_md_padding(message: &[u8]) -> usize {
    let mut message_modified: Vec<u8> = message.into_iter().cloned().collect();
    let mut padding = 0;
    let mac_length_base = authentificate_message(message).len();
    let padding_value = loop {
        message_modified.push(0);
        // dbg!(&message_modified.len());
        let mac_length = authentificate_message(&message_modified).len();
        // dbg!(&mac_length);
        if mac_length > mac_length_base {
            break (padding);
        }
        // dbg!(padding);
        padding += 1;
    };
    padding_value
}

fn ex28() {
    let message = b"test";
    authentificate_message(message);
}

fn authentificate_message(message: &[u8]) -> Vec<u8> {
    let key;
    unsafe {
        key = KEY.clone();
    }
    let mut input = key;
    input.extend(message);
    dbg!(input.len());
    let mut hasher = Sha1::new();
    hasher.update(input);
    let hash = hasher.finalize();
    hash.to_vec()
}

fn ex27() {
    let key;
    unsafe {
        key = KEY.clone();
    }
    let message = c_str_to_bytes("111111111111111122222222222222223333333333333333");
    let encrypted = encrypt_cbc(&message, &key, &key);
    // attack
    let fake_encrypted: Vec<u8> = encrypted
        .clone()
        .into_iter()
        .take(16)
        .chain(std::iter::repeat(0).take(16))
        .chain(encrypted.into_iter().take(16))
        .collect();
    let res_admin = decode_cbc_find_admin(&fake_encrypted);
    match res_admin {
        Ok(_) => (),
        Err(ascii_error) => {
            let bytes_err = c_str_to_bytes(&ascii_error.message);
            let bytes_block1: Vec<u8> = bytes_err.clone().into_iter().take(16).collect();
            let bytes_block3: Vec<u8> = bytes_err.into_iter().skip(32).take(16).collect();
            let key_decoded = fixed_xor(&bytes_block1, &bytes_block3);
            assert_eq!(key_decoded, key)
        }
    }
}

#[derive(Debug)]
struct HighAsciiError {
    message: String,
}

fn decode_cbc_find_admin(input_bytes: &[u8]) -> Result<bool, HighAsciiError> {
    let key;
    unsafe {
        key = KEY.clone();
    }
    let bytes_decoded = decrypt_cbc(input_bytes, &key, &key);
    if bytes_decoded.iter().any(|&b| b > 127) {
        return Err(HighAsciiError {
            message: bytes_as_string(&bytes_decoded),
        });
    }
    let string_decoded = bytes_as_string(&pkcs_validation(&bytes_decoded).unwrap());
    dbg!(&string_decoded);
    Ok(string_decoded
        .split(';')
        .any(|substr| substr == "admin=true"))
}

fn ex26() {
    // attack
    let admin_ctr_encoded = create_admin_ctr();
    assert!(decode_ctr_find_admin(&admin_ctr_encoded));
}

fn create_admin_ctr() -> Vec<u8> {
    let prepend = "comment1=cooking%20MCs;userdata=";
    let append = c_str_to_bytes(";comment2=%20like%20a%20pound%20of%20bacon");
    let admin = c_str_to_bytes(";admin=true;");
    let flips: Vec<u8> = append
        .into_iter()
        .zip(admin.into_iter())
        .map(|(original, new)| original ^ new)
        .collect();

    let base_encryption = encode_ctr_with_prepend_and_append("");

    let admin_encode: Vec<u8> = base_encryption
        .iter()
        .skip(prepend.len())
        .zip(flips.into_iter())
        .map(|(base_e, flip)| base_e ^ flip)
        .collect();

    let modified_encryption: Vec<u8> = base_encryption
        .into_iter()
        .take(prepend.len())
        .chain(admin_encode.into_iter())
        .collect();
    modified_encryption
}

fn decode_ctr_find_admin(input_bytes: &[u8]) -> bool {
    let key;
    unsafe {
        key = KEY.clone();
    }
    let bytes_decoded = ctr_encrypt(input_bytes, &key, 0);
    let string_decoded = bytes_as_string(&bytes_decoded);
    dbg!(&string_decoded);
    string_decoded
        .split(';')
        .any(|substr| substr == "admin=true")
}

fn encode_ctr_with_prepend_and_append(input_string: &str) -> Vec<u8> {
    let key;
    unsafe {
        key = KEY.clone();
    }
    let prepend = "comment1=cooking%20MCs;userdata=";
    let append = ";comment2=%20like%20a%20pound%20of%20bacon";
    let quoted_input = quote_out_special_chars(input_string);
    let string_to_encrypt = format!("{}{}{}", prepend, quoted_input, append);
    let bytes_input = c_str_to_bytes(&string_to_encrypt);
    ctr_encrypt(&bytes_input, &key, 0)
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

fn ex25() {
    let message_plain = ex7();

    // setup
    let nonce = 0;
    let key;
    unsafe {
        key = KEY.clone();
    }
    let encoded = ctr_encrypt(&message_plain, &key, nonce);

    // attack
    let plaintext = edit_cipher(&encoded, 0, &encoded);
    dbg!(bytes_as_string(&plaintext));
}

fn ex7() -> Vec<u8> {
    let key_string = "YELLOW SUBMARINE".to_string();
    let key = c_str_to_bytes(&key_string);
    let file_contents = include_str!("../data/encrypted_ECB_AES-128.txt");
    let contents = &file_contents.replace("\n", "");
    let bytes = b64_to_bytes(&contents);
    let cipher = Cipher::aes_128_ecb();
    let mut ctx = CipherCtx::new().unwrap();
    ctx.decrypt_init(Some(cipher), Some(&key), None).unwrap();
    let mut plaintext = vec![];
    ctx.cipher_update_vec(&bytes, &mut plaintext).unwrap();
    ctx.cipher_final_vec(&mut plaintext).unwrap();
    let message: String = bytes_as_string(&plaintext);
    dbg!(message);
    plaintext
}

fn edit_cipher(ciphertext: &[u8], offset: usize, newtext: &[u8]) -> Vec<u8> {
    assert!(offset + newtext.len() <= ciphertext.len());
    let nonce = 0;
    let key;
    unsafe {
        key = KEY.clone();
    }
    let mut plaintext = ctr_encrypt(ciphertext, &key, nonce);
    for i_replace in 0..newtext.len() {
        plaintext[offset + i_replace] = newtext[i_replace];
    }
    let new_encode = ctr_encrypt(&plaintext, &key, nonce);
    new_encode
}

fn ctr_encrypt(to_encode: &[u8], key: &[u8], nonce: u64) -> Vec<u8> {
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
