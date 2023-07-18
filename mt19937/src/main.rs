const W_MT: u32 = 32;
const N_MT: usize = 624;
const M_MT: u32 = 397;
const R_MT: u32 = 31;
const U_MT: u32 = 11;
const S_MT: u32 = 7;
const T_MT: u32 = 15;
const L_MT: u32 = 18;
const F_MT: u32 = 1812433253;
static A_MT: u32 = 0x9908B0DFu32;
static D_MT: u32 = 0xFFFFFFFFu32;
static B_MT: u32 = 0x9D2C5680u32;
static C_MT: u32 = 0xEFC60000u32;

mod utils;
use crate::utils::c_str_to_bytes;
use crate::utils::fixed_xor;
use std::io::Read;
use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    ex21();
    ex22();
    ex23();
    ex24();
}

fn ex21() {
    let mut mt19937 = MT19937::init();
    mt19937.seed_mt(5489);
    dbg!(mt19937.extract_number());
}

fn ex22() {
    let current_time = get_timestamp();
    let wait_time_1 = 45;
    let seed_oracle = current_time + wait_time_1;
    let mut mt19937 = MT19937::init();
    mt19937.seed_mt(seed_oracle);
    dbg!(seed_oracle);
    let number_gen = mt19937.extract_number();
    let wait_time_2 = 900;
    let start_time_hack = seed_oracle + wait_time_2;
    dbg!(get_seed(start_time_hack, number_gen));
}

fn ex23() {
    let y_test = 621342344u32;
    let y_shift = y_test ^ ((y_test << S_MT) & B_MT);
    let y_recover = invert_left_shift_and(y_shift, S_MT, B_MT);
    assert_eq!(y_test, y_recover);
    let y_shift_2 = y_test ^ ((y_test >> S_MT) & B_MT);
    let y_recover = invert_right_shift_and(y_shift_2, S_MT, B_MT);
    assert_eq!(y_test, y_recover);
    let hidden_state = 12;
    let tamper = MT19937::tamper(hidden_state);
    let inverted_tamper = invert_tampering(tamper);
    assert_eq!(inverted_tamper, hidden_state);

    // setup
    let seed = 2035253;
    let mut mt19937 = MT19937::init();
    mt19937.seed_mt(seed);

    // attack
    let mut vec_state = vec![0; 624];
    for i_state in 0..624 {
        let output = mt19937.extract_number();
        let state = invert_tampering(output);
        vec_state[i_state] = state;
    }
    let mut mt_clone = MT19937::clone_from_state(vec_state);
    for i_state in 0..624 {
        assert_eq!(mt_clone.mt[i_state], mt19937.mt[i_state]);
    }
    assert_eq!(mt_clone.extract_number(), mt19937.extract_number());
}

fn ex24() {
    let seed = 1 << 15;
    let mut mt19937 = MT19937::init();
    mt19937.seed_mt(seed);
    let mut mt19937_bis = MT19937::init();
    mt19937_bis.seed_mt(seed);

    let message = c_str_to_bytes(&std::iter::repeat('A').take(14).collect::<String>());
    let encrypted = encrypt_mt(&message.clone(), &mut mt19937);
    let decrypted = encrypt_mt(&encrypted, &mut mt19937_bis);
    assert_eq!(decrypted, message);

    // setup
    let mut mt19937 = MT19937::init();
    mt19937.seed_mt(seed);
    let encrypted = encrypt_with_prefix(&message, &mut mt19937);

    // attack
    for potential_seed in 0..u16::MAX {
        let mut mt_test = MT19937::init();
        mt_test.seed_mt(potential_seed as u32);
        let potential_decryption = encrypt_mt(&encrypted, &mut mt_test);
        if &potential_decryption[potential_decryption.len() - 14..potential_decryption.len()]
            == &message
        {
            dbg!(potential_seed);
        }
    }
}

fn encrypt_with_prefix(raw_message: &Vec<u8>, mt19937: &mut MT19937) -> Vec<u8> {
    let mut message_prefixed = vec![12, 52, 65, 15];
    message_prefixed.extend(raw_message);
    dbg!(&message_prefixed);
    encrypt_mt(&message_prefixed, mt19937)
}

fn encrypt_mt(message: &Vec<u8>, mt19937: &mut MT19937) -> Vec<u8> {
    // 500 bytes of stream cipher
    let keystream: Vec<u8> = (0..)
        .flat_map(|_| {
            let cipher = mt19937.extract_number();
            (0..4)
                .map(|i| ((cipher >> (i * 8)) % (1 << 8)) as u8)
                .collect::<Vec<u8>>()
                .into_iter()
        })
        .take(500)
        .collect();
    fixed_xor(&message, &keystream)
}

fn invert_tampering(output: u32) -> u32 {
    let mut output_untampered = output ^ (output >> L_MT);
    output_untampered ^= (output_untampered << T_MT) & C_MT;
    output_untampered = invert_left_shift_and(output_untampered, S_MT, B_MT);
    output_untampered = invert_right_shift_and(output_untampered, U_MT, D_MT);
    output_untampered
}

fn invert_right_shift_and(output: u32, shift: u32, and: u32) -> u32 {
    let mut last_range_correct = output;
    let num_range = 32 / shift;
    let mut mask = ((1 << shift) - 1) << (32 - shift);
    for _ in 1..(num_range + 1) {
        mask = mask >> shift;
        last_range_correct ^= (last_range_correct >> shift) & and & mask;
    }
    last_range_correct
}
fn invert_left_shift_and(output: u32, shift: u32, and: u32) -> u32 {
    let mut last_range_correct = output;
    let num_range = 32 / shift;
    let mut mask = (1 << shift) - 1;
    for _ in 1..(num_range + 1) {
        mask = mask << shift;
        last_range_correct ^= (last_range_correct << shift) & and & mask;
    }
    last_range_correct
}

fn get_seed(start_time_hack: u32, number_gen: u32) -> u32 {
    ((start_time_hack - 2000)..start_time_hack)
        .into_iter()
        .find_map(|potential_seed| {
            let mut mt19937 = MT19937::init();
            mt19937.seed_mt(potential_seed);
            let test_num = mt19937.extract_number();
            if test_num == number_gen {
                Some(potential_seed)
            } else {
                None
            }
        })
        .unwrap()
}

fn get_timestamp() -> u32 {
    let start = SystemTime::now();
    let since_the_epoch = start
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards");
    (since_the_epoch.as_secs() % (1 << 32)) as u32
}

impl MT19937 {
    fn init() -> MT19937 {
        let mt = vec![0; N_MT];
        let index = N_MT + 1;
        let lower_mask = (1 << R_MT) - 1;
        let not_lower = u32::MAX - lower_mask;
        let upper_mask = not_lower;
        MT19937 {
            mt,
            index,
            lower_mask,
            upper_mask,
        }
    }

    fn clone_from_state(mt: Vec<u32>) -> MT19937 {
        let index = N_MT;
        let lower_mask = (1 << R_MT) - 1;
        let not_lower = u32::MAX - lower_mask;
        let upper_mask = not_lower;
        MT19937 {
            mt,
            index,
            lower_mask,
            upper_mask,
        }
    }

    fn seed_mt(&mut self, seed: u32) {
        self.index = N_MT;
        self.mt[0] = seed;
        for i_generator in 1..N_MT {
            let tmp = F_MT
                .wrapping_mul(self.mt[i_generator - 1] ^ (self.mt[i_generator - 1] >> (W_MT - 2)))
                .wrapping_add(i_generator as u32);
            self.mt[i_generator] = tmp;
        }
    }

    fn extract_number(&mut self) -> u32 {
        if self.index >= N_MT {
            if self.index > N_MT {
                panic!("Generator not seeded")
            }
            self.twist()
        }
        let state = self.mt[self.index];
        let y = Self::tamper(state);
        self.index += 1;
        y
    }

    pub fn tamper(state: u32) -> u32 {
        let mut y = state;
        y = y ^ ((y >> U_MT) & D_MT);
        y = y ^ ((y << S_MT) & B_MT);
        y = y ^ ((y << T_MT) & C_MT);
        y = y ^ (y >> L_MT);
        y
    }

    fn twist(&mut self) {
        for i_mt in 0..N_MT {
            let x =
                (self.mt[i_mt] & self.upper_mask) | (self.mt[(i_mt + 1) % N_MT] & self.lower_mask);
            let mut xa = x >> 1;
            if x % 2 == 1 {
                xa ^= A_MT;
            }
            self.mt[i_mt] = self.mt[(i_mt + M_MT as usize) % N_MT] ^ xa;
        }
        self.index = 0;
    }
}

struct MT19937 {
    mt: Vec<u32>,
    index: usize,
    lower_mask: u32,
    upper_mask: u32,
}
