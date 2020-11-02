use blake2b::blake2xb::Iter;
use blake2b::Blake2xb;

pub fn new_blake2xb(buffer: Vec<u8>) -> Iter {
    if buffer.len() as u32 > 64 {
        let seed1: &[u8] = &buffer.as_slice()[0..64];
        let seed2: &[u8] = &buffer.as_slice()[64..];
        let mut hash = Blake2xb::keyed(None, seed1.as_ref());
        hash.update(seed2);
        return hash.finish();
    } else {
        let hash = Blake2xb::keyed(None, buffer.as_slice()).finish();
        return hash;
    }
}
