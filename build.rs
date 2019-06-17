pub use blake2b_rs::{Blake2b, Blake2bBuilder};
use includedir_codegen::Compression;

use std::{
    env,
    fs::File,
    io::{BufWriter, Read, Write},
    path::Path,
};

const SECP_PATH: &str = "specs/cells/secp256k1_blake160_sighash_all";
const BUF_SIZE: usize = 8 * 1024;
const CKB_HASH_PERSONALIZATION: &[u8] = b"ckb-default-hash";

fn main() {
    let mut bundled = includedir_codegen::start("BUNDLED_CELL");
    let mut buf = [0u8; BUF_SIZE];

    bundled
        .add_file(SECP_PATH, Compression::Gzip)
        .expect("add files to resource bundle");

    // build hash
    let mut blake2b = new_blake2b();
    let mut fd = File::open(SECP_PATH).expect("open file");
    loop {
        let read_bytes = fd.read(&mut buf).expect("read file");
        if read_bytes > 0 {
            blake2b.update(&buf[..read_bytes]);
        } else {
            break;
        }
    }

    let mut hash = [0u8; 32];
    blake2b.finalize(&mut hash);

    assert_eq!(
        "f1951123466e4479842387a66fabfd6b65fc87fd84ae8e6cd3053edb27fff2fd",
        &faster_hex::hex_string(&hash).unwrap()
    );

    bundled.build("bundled.rs").expect("build resource bundle");

    let out_path = Path::new(&env::var("OUT_DIR").unwrap()).join("code_hashes.rs");
    let mut out_file = BufWriter::new(File::create(&out_path).expect("create code_hashes.rs"));

    write!(
        &mut out_file,
        "pub const {}: [u8; 32] = {:?};",
        format!(
            "CODE_HASH_{}",
            "secp256k1_blake160_sighash_all".to_uppercase()
        ),
        hash
    )
    .expect("write to code_hashes.rs");
}

pub fn new_blake2b() -> Blake2b {
    Blake2bBuilder::new(32)
        .personal(CKB_HASH_PERSONALIZATION)
        .build()
}
