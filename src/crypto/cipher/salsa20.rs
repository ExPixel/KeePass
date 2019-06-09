use std::io::Read;
use super::BlockCipher;
use crate::memutil::read32_le;

const SIGMA: [u32; 4] = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574];

pub struct Salsa20 {
    state: [u32; 16],
}

impl Salsa20 {
    pub fn new(key: &[u8], nonce: &[u8]) -> Salsa20 {
        assert!(key.len() == 32, "Key length must be 32 bytes.");
        assert!(nonce.len() == 8, "Nonce length must be 8 bytes.");

        Salsa20 {
            state: [
                SIGMA[0],
                read32_le(key,  0),
                read32_le(key,  4),
                read32_le(key,  8),
                read32_le(key, 12),
                SIGMA[1],
                read32_le(nonce, 0),
                read32_le(nonce, 4),
                0, 0, // Counter
                SIGMA[2],
                read32_le(key, 16),
                read32_le(key, 20),
                read32_le(key, 24),
                read32_le(key, 28),
                SIGMA[3],
            ],
        }
    }
}

impl BlockCipher for Salsa20 {
    fn next_block(&mut self, dest: &mut [u8]) {
        macro_rules! quarter_round {
            ($State: expr, $A:expr, $B:expr, $C:expr, $D:expr) => {
                $State[$B] ^= ($State[$A].wrapping_add($State[$D])).rotate_left( 7);
                $State[$C] ^= ($State[$B].wrapping_add($State[$A])).rotate_left( 9);
                $State[$D] ^= ($State[$C].wrapping_add($State[$B])).rotate_left(13);
                $State[$A] ^= ($State[$D].wrapping_add($State[$C])).rotate_left(18);
            }
        }

        assert!(dest.len() >= 64, "Dest must be at least 64 bytes in length.");

        let mut working_state = unsafe {
            std::slice::from_raw_parts_mut(dest.as_mut_ptr() as *mut u32, 16)
        };
        working_state.copy_from_slice(&self.state);

        for _ in 0..10 {
            quarter_round!(working_state,  0,  4,  8, 12);
            quarter_round!(working_state,  5,  9, 13,  1);
            quarter_round!(working_state, 10, 14,  2,  6);
            quarter_round!(working_state, 15,  3,  7, 11);
            quarter_round!(working_state,  0,  1,  2,  3);
            quarter_round!(working_state,  5,  6,  7,  4);
            quarter_round!(working_state, 10, 11,  8,  9);
            quarter_round!(working_state, 15, 12, 13, 14);
        }

        for idx in 0..self.state.len() {
            working_state[idx] = self.state[idx].wrapping_add(working_state[idx]);
        }

        let (counter0, overflow) = self.state[8].overflowing_add(1);
        if overflow {
            if let Some(res) = self.state[9].checked_add(1) {
                self.state[9] = res;
            } else {
                panic!("Salsa20 block counter overflow.");
            }
        }
        self.state[8] = counter0;


        // If we're not already on a little-endian platform, we reverse the byte order
        // of the words in the working state:
        #[cfg(target_endian = "big")]
        {
            for word in working_state.iter_mut() {
                *word = (*word).swap_bytes();
            }
        }
    }
}

// impl CtrBlockCipher for Salsa20 {
//     fn apply_keystream(&mut self, data: &mut [u8]) {
//         let mut idx = 0;
//         let mut block = [0u8; 64];

//         while idx < data.len() {
//             self.next_block(&mut block);
//             crate::memutil::xor_slices(&mut data[idx..], &block); // This will automatically trim the slices.
//             idx += block.len();
//         }
//     }
// }

#[cfg(test)]
mod test {
    use super::Salsa20;

    #[test]
    pub fn salsa20_test() {
        let expected = [
            0x5E, 0x5E, 0x71, 0xF9, 0x01, 0x99, 0x34, 0x03, 0x04, 0xAB, 0xB2, 0x2A, 0x37, 0xB6, 0x62, 0x5B,
            0xF8, 0x83, 0xFB, 0x89, 0xCE, 0x3B, 0x21, 0xF5, 0x4A, 0x10, 0xB8, 0x10, 0x66, 0xEF, 0x87, 0xDA,
            0x30, 0xB7, 0x76, 0x99, 0xAA, 0x73, 0x79, 0xDA, 0x59, 0x5C, 0x77, 0xDD, 0x59, 0x54, 0x2D, 0xA2,
            0x08, 0xE5, 0x95, 0x4F, 0x89, 0xE4, 0x0E, 0xB7, 0xAA, 0x80, 0xA8, 0x4A, 0x61, 0x76, 0x66, 0x3F,
        ];

        let test_key = [
            0x0F, 0x62, 0xB5, 0x08, 0x5B, 0xAE, 0x01, 0x54,
            0xA7, 0xFA, 0x4D, 0xA0, 0xF3, 0x46, 0x99, 0xEC,
            0x3F, 0x92, 0xE5, 0x38, 0x8B, 0xDE, 0x31, 0x84,
            0xD7, 0x2A, 0x7D, 0xD0, 0x23, 0x76, 0xC9, 0x1C,
        ];

        let test_nonce = [ 0x28, 0x8F, 0xF6, 0x5D, 0xC4, 0x2B, 0x92, 0xF9 ];

        let mut salsa = Salsa20::new(&test_key, &test_nonce);
        let mut buf = [0u8; 64];
        salsa.next_block(&mut buf);

        assert_eq!(&expected[0..], &buf[0..]);
    }
}
