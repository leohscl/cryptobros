const W_MT: u32 = 32;
const N_MT: usize = 624;
const M_MT: u32 = 397;
const R_MT: u32 = 31;
const U_MT: u32 = 11;
const S_MT: u32 = 7;
const T_MT: u32 = 15;
const L_MT: u32 = 18;
const F_MT: u32 = 1812433253;
static mut A_MT: u32 = 0x9908B0DFu32;
static mut D_MT: u32 = 0xFFFFFFFFu32;
static mut B_MT: u32 = 0x9D2C5680u32;
static mut C_MT: u32 = 0xEFC60000u32;

use std::time::{SystemTime, UNIX_EPOCH};

struct MT19937 {
    mt: Vec<u32>,
    index: usize,
    lower_mask: u32,
    upper_mask: u32,
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
        let mut y = self.mt[self.index];
        unsafe {
            y = y ^ ((y >> U_MT) & D_MT);
            y = y ^ ((y << S_MT) & B_MT);
            y = y ^ ((y << T_MT) & C_MT);
        }
        y = y ^ (y >> L_MT);
        self.index += 1;
        y
    }

    fn twist(&mut self) {
        for i_mt in 0..N_MT {
            let x =
                (self.mt[i_mt] & self.upper_mask) | (self.mt[(i_mt + 1) % N_MT] & self.lower_mask);
            let mut xa = x >> 1;
            if x % 2 == 1 {
                unsafe {
                    xa ^= A_MT;
                }
            }
            self.mt[i_mt] = self.mt[(i_mt + M_MT as usize) % N_MT] ^ xa;
        }
        self.index = 0;
    }
}

fn main() {
    ex21();
    ex22();
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
