use crate::vdict::VariantDict;
use crate::database::PwUUID;
use crate::context::Context;
use crate::error::Error;

#[derive(Clone)]
pub struct KdfParameters {
    pub kdf_uuid: PwUUID,
    pub dict: VariantDict,
}

impl KdfParameters {
    pub const PARAM_UUID: &'static str = "$UUID";

    pub fn new(kdf_uuid: PwUUID) -> KdfParameters {
        KdfParameters { kdf_uuid, dict: VariantDict::new() }
    }

    pub fn serialize<W: std::io::Write>(src: &KdfParameters, out: W) -> Result<(), Error> {
        VariantDict::serialize(&src.dict, out)
    }

    pub fn deserialize<R: std::io::Read>(dest: &mut KdfParameters, data: R) -> Result<(), Error> {
        VariantDict::deserialize(&mut dest.dict, data)?;
        if let Some(uuid_data) = dest.dict.get_arr(Self::PARAM_UUID) {
            if uuid_data.len() != PwUUID::SIZE {
                return Err(Error::BadFormat("Invalid UUID."));
            } else {
                let uuid = PwUUID::from_slice(uuid_data);
                dest.kdf_uuid = uuid;
            }
        } else {
            return Err(Error::BadFormat("VariantDictionary for KdfParameters is missing UUID field."));
        }
        Ok(())
    }

    pub fn clear(&mut self) {
        self.dict.clear();
    }
}

// @TODO change this to be more like the static ciphers
static KDF_ENGINE_AES: KdfEngine = KdfEngine::Aes;
static KDF_ENGINE_ARGON2: KdfEngine = KdfEngine::Argon2;

pub fn get_kdf_engine(uuid: &PwUUID) -> Option<&'static KdfEngine> {
    match *uuid {
        aes::UUID => Some(&KDF_ENGINE_AES),
        argon2::UUID => Some(&KDF_ENGINE_ARGON2),
        _ => None,
    }
}

#[derive(Clone)]
pub enum KdfEngine {
    Aes,
    Argon2,
}

impl KdfEngine {
    pub fn uuid(&self) -> PwUUID {
        match self {
            &KdfEngine::Aes => aes::UUID,
            &KdfEngine::Argon2 => argon2::UUID,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            &KdfEngine::Aes => aes::NAME,
            &KdfEngine::Argon2 => argon2::NAME,
        }
    }

    pub fn transform(&self, msg: &[u8], params: &KdfParameters) -> Result<[u8; 32], Error> {
        match self {
            &KdfEngine::Aes => aes::transform(msg, params),
            &KdfEngine::Argon2 => argon2::transform(msg, params),
        }
    }

    pub fn randomize(&self, context: &mut Context, params: &mut KdfParameters) {
        match self {
            &KdfEngine::Aes => aes::randomize(context, params),
            &KdfEngine::Argon2 => argon2::randomize(context, params),
        }
    }

    pub fn default_parameters(&self) -> KdfParameters {
        match self {
            &KdfEngine::Aes => aes::default_parameters(),
            &KdfEngine::Argon2 => argon2::default_parameters(),
        }
    }

    pub fn best_parameters(&self, millis: u64) -> KdfParameters {
        match self {
            &KdfEngine::Aes => aes::best_parameters(millis),
            &KdfEngine::Argon2 => argon2::best_parameters(millis),
        }
    }

    ///  Maximizes a parameter within a given time frame.
    pub fn maximize_param_uint64(&self, p: &mut KdfParameters, name: &str, mut umin: u64, mut umax: u64, umillis: u64, interp_search: bool) -> Result<(), Error> {
        // For now the default implementation is always called. I'm not aware of a KdfEngine in
        // KeePass that uses another implementation.
        self.default_maximize_param_uint64(p, name, umin, umax, umillis, interp_search)
    }

    fn default_maximize_param_uint64(&self, p: &mut KdfParameters, name: &str, mut umin: u64, mut umax: u64, umillis: u64, interp_search: bool) -> Result<(), Error> {

        macro_rules! time_millis {
            ($Expr:expr) => ({
                let start = std::time::Instant::now();
                $Expr;
                start.elapsed().as_millis()
            })
        }

        debug_assert!(name.len() > 0, "`name` must not be an empty string.");

        debug_assert!(umax <= (std::u64::MAX >> 1), "UMax cannot be greater than 0x7FFFFFFFFFFFFFFFF");

        if umax > (std::u64::MAX >> 1) {
            umax = std::u64::MAX >> 1;

            if umin > umax {
                p.dict.set_u64(name, umin);
                return Ok(())
            }
        }

        let mut msg = [0u8; 32];
        msg.iter_mut().enumerate().for_each(|(idx, cell)| *cell = idx as u8);

        let mut ulow = umin;
        let mut uhigh = umin + 1;
        let mut tlow = 0;
        let mut thigh = 0;
        let mut ttarget = umillis;

        // Determine range.
        while uhigh < umax {
            p.dict.set_u64(name, uhigh);

            let start_instant = std::time::Instant::now();
            self.transform(&msg, p)?;
            thigh = start_instant.elapsed().as_millis() as u64;

            if thigh > ttarget {
                break
            }

            ulow = uhigh;
            tlow = thigh;
            uhigh <<= 1;
        }
        if uhigh > umax { uhigh = umax; thigh = 0; }
        if ulow < uhigh { ulow = uhigh; } // skips to end

        // Find optimal number of iterations.
        while (uhigh - ulow) > 2 {
            let mut u = (uhigh - ulow) >> 1; // Binary Search
            // Interpolation search, if possible
            if interp_search && (tlow > 0) && (thigh > ttarget) && (tlow <= ttarget) {
                u = ulow + (((uhigh - ulow) * (ttarget - tlow)) / (thigh - tlow));
                if (u >= ulow) && (u <= uhigh) {
                    u = std::cmp::max(u, ulow + 1);
                    u = std::cmp::min(u, uhigh - 1);
                } else {
                    // to be honest, I haven't been paying enough attention to this part of the
                    // code to know why getting here is bad.
                    debug_assert!(false, "shouldn't be here");
                    u = (uhigh + ulow) >> 1;
                }
            }

            p.dict.set_u64(name, u);

            let start_instant = std::time::Instant::now();
            self.transform(&msg, p)?;
            let t = start_instant.elapsed().as_millis() as u64;

            if t == ttarget { ulow = u; break; }
            else if t > ttarget { uhigh = u; thigh = t; }
            else { ulow = u; tlow = t; }
        }

        p.dict.set_u64(name, ulow);

        Ok(())
    }
}

pub mod aes {
    use super::KdfParameters;
    use crate::constants;
    use crate::database::PwUUID;
    use crate::context::Context;
    use crate::error::Error;
    use sha2::{Sha256, Digest};

    pub const UUID: PwUUID = PwUUID::wrap([
        0xC9, 0xD9, 0xF3, 0x9A, 0x62, 0x8A, 0x44, 0x60,
        0xBF, 0x74, 0x0D, 0x08, 0xC1, 0x8A, 0x4F, 0xEA,
    ]);

    pub const NAME: &str = "AES-KDF";

    pub const PARAM_ROUNDS: &str = "R";
    pub const PARAM_SEED: &str = "S";

    pub const BENCH_STEP: u64 = 3001;

    pub fn default_parameters() -> KdfParameters {
        let mut p = KdfParameters::new(UUID);
        p.dict.set_u64(PARAM_ROUNDS, constants::DEFAULT_KEY_ENCRYPTION_ROUNDS);
        return p;
    }

    pub fn randomize(context: &mut Context, p: &mut KdfParameters) {
        debug_assert!(UUID == p.kdf_uuid, "UUID of parameters does not match");
        let mut seed = Vec::with_capacity(32);
        seed.resize(32, 0);
        context.crypto_random.get_random_bytes(&mut seed);
        p.dict.set_arr(PARAM_SEED, seed);
    }

    pub fn transform(msg: &[u8], p: &KdfParameters) -> Result<[u8; 32], Error> {
        let rounds = p.dict.get_u64(PARAM_ROUNDS).ok_or(Error::Generic("Missing KDF Paramater `Rounds`."))?;
        let seed = p.dict.get_arr(PARAM_SEED).ok_or(Error::Generic("Missing KDF Parameter `Seed`."))?;

        // @TODO KeePass actually accepts a message and seed length that is not 32 bytes in release mode.
        //       It just uses the SHA256 hash of the message or seed.
        debug_assert!(msg.len() == 32, "expected a message length of 32");
        debug_assert!(seed.len() == 32, "expected a seed length of 32");

        if msg.len() != 32 {
            return Err(Error::Generic("Expected a message length of 32."));
        }

        if seed.len() != 32 {
            return Err(Error::Generic("Expected a seed length of 32."));
        }

        return transform_key(msg, seed, rounds);
    }

    pub fn transform_key(original_key_32: &[u8], key_seed_32: &[u8], rounds: u64) -> Result<[u8; 32], Error> {
        assert!(original_key_32.len() == 32, "Key length must be 32 bytes.");
        assert!(key_seed_32.len() == 32, "Seed length must be 32 bytes.");

        let mut new_key = [0u8; 32];
        new_key.copy_from_slice(original_key_32);
        transform_key_256(&mut new_key, &key_seed_32, rounds);

        let mut hasher = Sha256::new();
        hasher.input(&new_key);

        /// I just overwrite the new_key array with the hashed value.
        new_key.copy_from_slice(&hasher.result());
        Ok((new_key))
    }

    pub fn transform_key_256(new_key: &mut [u8], key_seed_32: &[u8], rounds: u64) {
        use aes::Aes256;
        use aes::block_cipher_trait::generic_array::GenericArray;
        use aes::block_cipher_trait::BlockCipher;

        assert!(key_seed_32.len() == 32, "The key must be 32 bytes (256 bits) long.");
        assert!(new_key.len() % 16 == 0, "The size of data must be a multiple of 16.");

        let cipher = Aes256::new(GenericArray::from_slice(key_seed_32));

        for _ in 0..rounds {
            for block in new_key.chunks_mut(16) {
                let mut block = GenericArray::from_mut_slice(block);
                cipher.encrypt_block(&mut block);
            }
        }
    }


    /// Returns the best parameters to to use in order to have the KDF run for a given number of
    /// milliseconds.
    pub fn best_parameters(millis: u64) -> KdfParameters {
        use aes::Aes256;
        use aes::block_cipher_trait::generic_array::GenericArray;
        use aes::block_cipher_trait::BlockCipher;

        let key = [0u8; 32];
        let mut data = [0u8; 32];
        let cipher = Aes256::new(GenericArray::from_slice(&key));

        let mut rounds = 0;
        let start = std::time::Instant::now();

        loop {
            for block in data.chunks_mut(16) {
                let mut block = GenericArray::from_mut_slice(block);
                cipher.encrypt_block(&mut block);
            }

            rounds += 1;

            let elapsed = start.elapsed().as_millis() as u64;
            if elapsed >= millis {
                break;
            }
        }

        let mut params = default_parameters();
        params.dict.set_u64(PARAM_ROUNDS, rounds);

        params
    }
}

pub mod argon2 {
    use super::KdfParameters;
    use crate::constants;
    use crate::database::PwUUID;
    use crate::context::Context;
    use crate::error::Error;
    use sha2::{Sha256, Digest};

    // @TODO
    pub const UUID: PwUUID = PwUUID::wrap([
        0xEF, 0x63, 0x6D, 0xDF, 0x8C, 0x29, 0x44, 0x4B,
        0x91, 0xF7, 0xA9, 0xA4, 0x03, 0xE3, 0x0A, 0x0C
    ]);

    pub const NAME: &str = "Argon2";

    pub fn default_parameters() -> KdfParameters {
        unimplemented!("argon2::default_parameters");
    }

    pub fn randomize(context: &mut Context, p: &mut KdfParameters) {
        unimplemented!("argon2::randomize");
    }

    pub fn transform(msg: &[u8], p: &KdfParameters) -> Result<[u8; 32], Error> {
        unimplemented!("argon2::transform");
    }

    pub fn best_parameters(millis: u64) -> KdfParameters {
        unimplemented!("argon2::best_parameters");
    }
}

#[cfg(test)]
mod test {
    use super::aes;

    /// Test out AES implementation to make sure we're getting the same results as KeePass.
    #[test]
    pub fn test_aes() {
        let mut key = [0u8; 32];
        let reference: [u8; 16] = [
            0x75, 0xD1, 0x1B, 0x0E, 0x3A, 0x68, 0xC4, 0x22,
            0x3D, 0x88, 0xDB, 0xF0, 0x17, 0x97, 0x7D, 0xD7,
        ];
        let mut data = [0u8; 16];
        data[0] = 0x04;
        aes::encrypt256(&key, &mut data, 1);
        assert_eq!(reference, data, "bad AES encryption");
    }
}
