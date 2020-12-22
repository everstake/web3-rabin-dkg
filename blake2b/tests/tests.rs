extern crate blake2b;
extern crate rustc_serialize;

use blake2b::{blake2b, blake2b_keyed, blake2xb_keyed, Blake2b};

#[test]
fn multiple_updates() {
    const DATA: [u8; 1110] = [0x55; 1110];
    const SIZES: [usize; 4] = [0, 5, 50, 500];

    let mut hasher = Blake2b::default();
    for &s in &SIZES {
        hasher.update(&DATA[..s]);
    }
    for &s in SIZES.iter().rev() {
        hasher.update(&DATA[..s]);
    }

    assert_eq!(hasher.finish(), blake2b(64, &DATA));
}

#[test]
fn selftest() {
    assert!(blake2b::selftest());
}

#[test]
fn testvectors() {
    use rustc_serialize::hex::FromHex;
    use rustc_serialize::json::{self};

    const KAT: &'static str = include_str!("blake2-kat.json");

    #[derive(RustcDecodable)]
    struct Data {
        hash: String,
        data: String,
        key: String,
        out: String,
    }

    let data: Vec<Data> = json::decode(KAT).unwrap();
    for d in data {
        let data = d.data.from_hex().unwrap();
        let key = d.key.from_hex().unwrap();
        let out = d.out.from_hex().unwrap();

        match &*d.hash {
            "blake2b" => {
                assert_eq!(&blake2b_keyed(out.len(), &key, &data), &out[..]);
            }
            "blake2xb" => {
                let mut hash = Vec::with_capacity(out.len());
                for h in blake2xb_keyed(Some(out.len() as u32), &key, &data) {
                    hash.extend_from_slice(&h);
                }

                assert_eq!(hash, out);
            }
            "blake2bp" => {}
            hash => {
                unreachable!(hash);
            }
        }
    }
}
