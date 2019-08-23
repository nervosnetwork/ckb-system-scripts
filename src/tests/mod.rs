mod dao;
mod secp256k1_blake160_sighash_all;
mod secp256k1_ripemd160_sha256_sighash_all;

use ckb_crypto::secp::Privkey;
use ckb_script::DataLoader;
use ckb_types::{
    bytes::Bytes,
    core::{cell::CellMeta, BlockExt, HeaderView, TransactionView},
    packed::{Byte32, CellOutput, OutPoint, Witness},
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
}

#[derive(Default)]
pub struct DummyDataLoader {
    pub cells: HashMap<OutPoint, (CellOutput, Bytes)>,
    pub headers: HashMap<Byte32, HeaderView>,
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
                .map(|(_, data)| (data.clone(), CellOutput::calc_data_hash(&data).pack()))
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
}

pub fn blake160(message: &[u8]) -> Bytes {
    Bytes::from(&ckb_hash::blake2b_256(message)[..20])
}

pub fn multi_sign_tx(tx: TransactionView, keys: &[&Privkey]) -> TransactionView {
    let tx_hash: H256 = tx.hash().unpack();
    let signed_witnesses: Vec<Witness> = tx
        .inputs()
        .into_iter()
        .enumerate()
        .map(|(i, _)| {
            let witness = tx.witnesses().get(i).unwrap_or_default();
            let mut blake2b = ckb_hash::new_blake2b();
            let mut message = [0u8; 32];
            blake2b.update(&tx_hash[..]);
            for data in witness.clone().into_iter() {
                blake2b.update(&data.raw_data());
            }
            blake2b.finalize(&mut message);
            let message = H256::from(message);
            let mut signed_witness: Vec<_> = keys
                .iter()
                .map(|key| {
                    let sig = key.sign_recoverable(&message).expect("sign");
                    Bytes::from(sig.serialize()).pack()
                })
                .collect();
            for data in witness.into_iter() {
                signed_witness.push(data);
            }
            signed_witness.pack()
        })
        .collect();
    // calculate message
    tx.as_advanced_builder()
        .set_witnesses(signed_witnesses)
        .build()
}

pub fn sign_tx(tx: TransactionView, key: &Privkey) -> TransactionView {
    multi_sign_tx(tx, &[key])
}
