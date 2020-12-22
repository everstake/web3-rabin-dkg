use blake2b::blake2xb::Iter;
use blake2b::Blake2xb;

/// Hash bytes using blake2xb algorithm
pub fn new_blake2xb(buffer: Vec<u8>) -> Iter {
    if buffer.len() > 64 {
        let seed1: &[u8] = &buffer[0..64];
        let seed2: &[u8] = &buffer[64..];
        let mut hash = Blake2xb::keyed(None, seed1);
        hash.update(seed2);
        hash.finish()
    } else {
        Blake2xb::keyed(None, &buffer).finish()
    }
}
