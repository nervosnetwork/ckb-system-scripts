mod dao;
mod secp256k1_blake160_sighash_all;
mod type_id;

use ckb_core::{
    cell::CellMeta,
    extras::BlockExt,
    transaction::{CellOutPoint, CellOutput, OutPoint, Transaction, TransactionBuilder, Witness},
    Bytes, Capacity,
};
use ckb_crypto::secp::{Generator, Privkey};
use ckb_script::DataLoader;
use lazy_static::lazy_static;
use numext_fixed_hash::H256;
use rand::{thread_rng, Rng};
use std::collections::HashMap;

pub const MAX_CYCLES: u64 = std::u64::MAX;

lazy_static! {
    pub static ref SIGHASH_ALL_BIN: Bytes =
        Bytes::from(&include_bytes!("../../specs/cells/secp256k1_blake160_sighash_all")[..]);
    pub static ref DAO_BIN: Bytes = Bytes::from(&include_bytes!("../../specs/cells/dao")[..]);
    pub static ref TYPE_ID_BIN: Bytes =
        Bytes::from(&include_bytes!("../../specs/cells/type_id")[..]);
}

#[derive(Default)]
pub struct DummyDataLoader {
    pub cells: HashMap<CellOutPoint, (CellOutput, Bytes)>,
}

impl DummyDataLoader {
    fn new() -> Self {
        Self::default()
    }
}

impl DataLoader for DummyDataLoader {
    // load Cell Data
    fn load_cell_data(&self, cell: &CellMeta) -> Option<Bytes> {
        cell.mem_cell_data.clone().or_else(|| {
            self.cells
                .get(&cell.out_point)
                .map(|(_, data)| data)
                .cloned()
        })
    }
    // load BlockExt
    fn get_block_ext(&self, _hash: &H256) -> Option<BlockExt> {
        unreachable!()
    }
}

pub fn sign_tx(tx: Transaction, key: &Privkey) -> Transaction {
    let signed_witnesses: Vec<Witness> = tx
        .inputs()
        .iter()
        .enumerate()
        .map(|(i, _)| {
            let witness = tx.witnesses().get(i).cloned().unwrap_or(vec![]);
            let mut blake2b = ckb_hash::new_blake2b();
            let mut message = [0u8; 32];
            blake2b.update(&tx.hash()[..]);
            for data in &witness {
                blake2b.update(&data);
            }
            blake2b.finalize(&mut message);
            let message = H256::from(message);
            let sig = key.sign_recoverable(&message).expect("sign");
            let mut signed_witness = vec![Bytes::from(sig.serialize())];
            for data in &witness {
                signed_witness.push(data.clone());
            }
            signed_witness
        })
        .collect();
    // calculate message
    TransactionBuilder::from_transaction(tx)
        .witnesses_clear()
        .witnesses(signed_witnesses)
        .build()
}

pub fn script_cell(script_data: &Bytes) -> (CellOutput, OutPoint) {
    let tx_hash = {
        let mut rng = thread_rng();
        let mut buf = [0u8; 32];
        rng.fill(&mut buf);
        H256::from(&buf)
    };
    let out_point = OutPoint::new_cell(tx_hash, 0);

    let cell = CellOutput::new(
        Capacity::bytes(script_data.len()).expect("script capacity"),
        CellOutput::calculate_data_hash(script_data),
        Default::default(),
        None,
    );

    (cell, out_point)
}

pub fn secp_code_hash() -> H256 {
    let (cell, _) = script_cell(&SIGHASH_ALL_BIN);
    cell.data_hash().to_owned()
}

pub fn dao_code_hash() -> H256 {
    let (cell, _) = script_cell(&DAO_BIN);
    cell.data_hash().to_owned()
}

pub fn type_id_code_hash() -> H256 {
    let (cell, _) = script_cell(&TYPE_ID_BIN);
    cell.data_hash().to_owned()
}

pub fn gen_lock() -> (Privkey, Vec<Bytes>) {
    let key_gen = Generator::new();
    let privkey = key_gen.random_privkey();
    let pubkey = privkey.pubkey().expect("pubkey");
    // compute pubkey hash
    let pubkey_hash = {
        let ser_pk = pubkey.serialize();
        ckb_hash::blake2b_256(ser_pk)[..20].to_vec()
    };
    let lock_args = vec![pubkey_hash.into()];
    (privkey, lock_args)
}
