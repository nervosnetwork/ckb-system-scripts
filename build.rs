pub use blake2b_rs::{Blake2b, Blake2bBuilder};
use includedir_codegen::Compression;

use std::{
    env,
    fs::File,
    io::{BufWriter, Read, Write},
    path::Path,
};

const PATH_PREFIX: &str = "specs/cells/";
const BUF_SIZE: usize = 8 * 1024;
const CKB_HASH_PERSONALIZATION: &[u8] = b"ckb-default-hash";

const BINARIES: &[(&str, &str)] = &[
    (
        "secp256k1_blake160_sighash_all",
        "2d75153097d640b4628ec31ed46863296c63a73edda24451827132bc33f04212",
    ),
    (
        "secp256k1_data",
        "9799bee251b975b82c45a02154ce28cec89c5853ecc14d12b7b8cccfc19e0af4",
    ),
    (
        "dao",
        "32543ae0401dec556640aee7ca37fd69edb42f1c08dc6175589821dc9b6a883a",
    ),
];

fn main() {
    let mut bundled = includedir_codegen::start("BUNDLED_CELL");

    let out_path = Path::new(&env::var("OUT_DIR").unwrap()).join("code_hashes.rs");
    let mut out_file = BufWriter::new(File::create(&out_path).expect("create code_hashes.rs"));

    for (name, expected_hash) in BINARIES {
        let path = format!("{}{}", PATH_PREFIX, name);

        let mut buf = [0u8; BUF_SIZE];
        bundled
            .add_file(&path, Compression::Gzip)
            .expect("add files to resource bundle");

        // build hash
        let mut blake2b = new_blake2b();
        let mut fd = File::open(&path).expect("open file");
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

        assert_eq!(expected_hash, &faster_hex::hex_string(&hash).unwrap());

        write!(
            &mut out_file,
            "pub const {}: [u8; 32] = {:?};\n",
            format!("CODE_HASH_{}", name.to_uppercase()),
            hash
        )
        .expect("write to code_hashes.rs");
    }

    bundled.build("bundled.rs").expect("build resource bundle");
}

pub fn new_blake2b() -> Blake2b {
    Blake2bBuilder::new(32)
        .personal(CKB_HASH_PERSONALIZATION)
        .build()
}
