mod dao;
mod secp256k1_blake160_multisig_all;
mod secp256k1_blake160_sighash_all;
mod secp256k1_ripemd160_sha256_sighash_all;

use ckb_crypto::secp::Privkey;
use ckb_script::DataLoader;
use ckb_types::{
    bytes::Bytes,
    core::{cell::CellMeta, BlockExt, EpochExt, HeaderView, TransactionView},
    packed::{self, Byte32, CellOutput, OutPoint},
    prelude::*,
    H256,
};
use lazy_static::lazy_static;
use std::collections::HashMap;

pub const MAX_CYCLES: u64 = std::u64::MAX;

lazy_static! {
    pub static ref SIGHASH_ALL_BIN: Bytes =
        Bytes::from(&include_bytes!("../../specs/cells/secp256k1_blake160_sighash_all")[..]);
    pub static ref BITCOIN_P2PKH_BIN: Bytes = Bytes::from(
        &include_bytes!("../../specs/cells/secp256k1_ripemd160_sha256_sighash_all")[..]
    );
    pub static ref SECP256K1_DATA_BIN: Bytes =
        Bytes::from(&include_bytes!("../../specs/cells/secp256k1_data")[..]);
    pub static ref DAO_BIN: Bytes = Bytes::from(&include_bytes!("../../specs/cells/dao")[..]);
    pub static ref MULTISIG_ALL_BIN: Bytes =
        Bytes::from(&include_bytes!("../../specs/cells/secp256k1_blake160_multisig_all")[..]);
}

#[derive(Default)]
pub struct DummyDataLoader {
    pub cells: HashMap<OutPoint, (CellOutput, Bytes)>,
    pub headers: HashMap<Byte32, HeaderView>,
    pub epoches: HashMap<Byte32, EpochExt>,
}

impl DummyDataLoader {
    fn new() -> Self {
        Self::default()
    }
}

impl DataLoader for DummyDataLoader {
    // load Cell Data
    fn load_cell_data(&self, cell: &CellMeta) -> Option<(Bytes, Byte32)> {
        cell.mem_cell_data.clone().or_else(|| {
            self.cells
                .get(&cell.out_point)
                .map(|(_, data)| (data.clone(), CellOutput::calc_data_hash(&data)))
        })
    }
    // load BlockExt
    fn get_block_ext(&self, _hash: &Byte32) -> Option<BlockExt> {
        unreachable!()
    }

    // load header
    fn get_header(&self, block_hash: &Byte32) -> Option<HeaderView> {
        self.headers.get(block_hash).cloned()
    }

    // load EpochExt
    fn get_block_epoch(&self, block_hash: &Byte32) -> Option<EpochExt> {
        self.epoches.get(block_hash).cloned()
    }
}

pub fn blake160(message: &[u8]) -> Bytes {
    Bytes::from(&ckb_hash::blake2b_256(message)[..20])
}

pub fn sign_tx(tx: TransactionView, key: &Privkey) -> TransactionView {
    let tx_hash = tx.hash();
    let signed_witnesses: Vec<packed::Bytes> = tx
        .inputs()
        .into_iter()
        .enumerate()
        .map(|(i, _)| {
            if i == 0 {
                let mut blake2b = ckb_hash::new_blake2b();
                let mut message = [0u8; 32];
                blake2b.update(&tx_hash.raw_data());
                let witness = tx.witnesses().get(0).unwrap();
                if !witness.raw_data().is_empty() {
                    blake2b.update(&witness.raw_data());
                }
                (1..tx.witnesses().len()).for_each(|n| {
                    let witness = tx.witnesses().get(n).unwrap();
                    if !witness.raw_data().is_empty() {
                        blake2b.update(&witness.raw_data());
                    }
                });
                blake2b.finalize(&mut message);
                let message = H256::from(message);
                let mut signed_witness = Bytes::new();
                let sig = key.sign_recoverable(&message).expect("sign");
                signed_witness.extend_from_slice(&sig.serialize());
                if !witness.raw_data().is_empty() {
                    signed_witness.extend_from_slice(&witness.raw_data());
                }
                signed_witness.pack()
            } else {
                tx.witnesses().get(i).unwrap_or_default()
            }
        })
        .collect();
    // calculate message
    tx.as_advanced_builder()
        .set_witnesses(signed_witnesses)
        .build()
}
