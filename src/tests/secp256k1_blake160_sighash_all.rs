use super::{rand_tx_hash, sign_tx, DummyDataLoader, MAX_CYCLES, SIGHASH_ALL_BIN};
use ckb_core::{
    cell::{CellMetaBuilder, ResolvedOutPoint, ResolvedTransaction},
    script::{Script, ScriptHashType},
    transaction::{CellInput, CellOutput, OutPoint, Transaction, TransactionBuilder},
    Bytes, Capacity,
};
use ckb_crypto::secp::{Generator, Privkey};
use ckb_script::{ScriptConfig, ScriptError, TransactionScriptsVerifier};
use numext_fixed_hash::H256;

fn gen_tx(dummy: &mut DummyDataLoader, script_data: Bytes, lock_args: Vec<Bytes>) -> Transaction {
    let previous_tx_hash = rand_tx_hash();
    let previous_index = 0;
    let capacity = Capacity::shannons(42);
    let previous_out_point = OutPoint::new_cell(previous_tx_hash, previous_index);
    let contract_tx_hash = rand_tx_hash();
    let contract_index = 0;
    let contract_out_point = OutPoint::new_cell(contract_tx_hash.clone(), contract_index);
    // dep contract code
    let dep_cell = CellOutput::new(
        Capacity::bytes(script_data.len()).expect("script capacity"),
        CellOutput::calculate_data_hash(&script_data),
        Default::default(),
        None,
    );
    let dep_cell_data_hash = dep_cell.data_hash().to_owned();
    dummy.cells.insert(
        contract_out_point.clone().cell.unwrap(),
        (dep_cell, script_data),
    );
    // input unlock script
    let previous_output_cell = CellOutput::new(
        capacity,
        Default::default(),
        Script::new(lock_args, dep_cell_data_hash, ScriptHashType::Data),
        None,
    );
    dummy.cells.insert(
        previous_out_point.clone().cell.unwrap(),
        (previous_output_cell, Bytes::new()),
    );
    TransactionBuilder::default()
        .input(CellInput::new(previous_out_point.clone(), 0))
        .dep(contract_out_point)
        .output(CellOutput::new(
            capacity,
            Default::default(),
            Default::default(),
            None,
        ))
        .output_data(Bytes::new())
        .build()
}

fn sign_tx_hash(tx: Transaction, key: &Privkey, tx_hash: &[u8]) -> Transaction {
    // calculate message
    let mut blake2b = ckb_hash::new_blake2b();
    let mut message = [0u8; 32];
    blake2b.update(tx_hash);
    blake2b.finalize(&mut message);
    let message = H256::from(message);
    let sig = key.sign_recoverable(&message).expect("sign");
    TransactionBuilder::from_transaction(tx)
        .witness(vec![Bytes::from(sig.serialize())])
        .build()
}

fn build_resolved_tx<'a>(
    data_loader: &DummyDataLoader,
    tx: &'a Transaction,
) -> ResolvedTransaction<'a> {
    let previous_out_point = tx.inputs()[0].previous_output.clone().cell.unwrap();
    let deps_out_point = tx.deps()[0].clone().cell.unwrap();
    let (dep_output, dep_data) = data_loader.cells.get(&deps_out_point).unwrap();
    let dep_cell = CellMetaBuilder::from_cell_output(dep_output.to_owned(), dep_data.to_owned())
        .out_point(deps_out_point)
        .build();
    let (input_output, input_data) = data_loader.cells.get(&previous_out_point).unwrap();
    let input_cell =
        CellMetaBuilder::from_cell_output(input_output.to_owned(), input_data.to_owned())
            .out_point(previous_out_point)
            .build();
    ResolvedTransaction {
        transaction: tx,
        resolved_deps: vec![ResolvedOutPoint::cell_only(dep_cell)],
        resolved_inputs: vec![ResolvedOutPoint::cell_only(input_cell)],
    }
}

#[test]
fn test_sighash_all_unlock() {
    let mut data_loader = DummyDataLoader::new();
    let key_gen = Generator::new();
    let privkey = key_gen.random_privkey();
    let pubkey = privkey.pubkey().expect("pubkey");
    // compute pubkey hash
    let pubkey_hash = {
        let ser_pk = pubkey.serialize();
        ckb_hash::blake2b_256(ser_pk)[..20].to_vec()
    };
    let tx = gen_tx(
        &mut data_loader,
        SIGHASH_ALL_BIN.clone(),
        vec![pubkey_hash.into()],
    );
    let tx = sign_tx(tx, &privkey);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    let script_config = ScriptConfig::default();
    let verify_result = TransactionScriptsVerifier::new(&resolved_tx, &data_loader, &script_config)
        .verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_signing_with_wrong_key() {
    let mut data_loader = DummyDataLoader::new();
    let key_gen = Generator::new();
    let privkey = key_gen.random_privkey();
    let wrong_privkey = key_gen.random_privkey();
    let pubkey = privkey.pubkey().expect("pubkey");
    // compute pubkey hash
    let pubkey_hash = {
        let ser_pk = pubkey.serialize();
        ckb_hash::blake2b_256(ser_pk)[..20].to_vec()
    };
    let tx = gen_tx(
        &mut data_loader,
        SIGHASH_ALL_BIN.clone(),
        vec![pubkey_hash.into()],
    );
    let tx = sign_tx(tx, &wrong_privkey);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    let script_config = ScriptConfig::default();
    let verify_result = TransactionScriptsVerifier::new(&resolved_tx, &data_loader, &script_config)
        .verify(MAX_CYCLES);
    assert_eq!(verify_result, Err(ScriptError::ValidationFailure(-3)));
}

#[test]
fn test_signing_wrong_tx_hash() {
    let mut data_loader = DummyDataLoader::new();
    let key_gen = Generator::new();
    let privkey = key_gen.random_privkey();
    let pubkey = privkey.pubkey().expect("pubkey");
    // compute pubkey hash
    let pubkey_hash = {
        let ser_pk = pubkey.serialize();
        ckb_hash::blake2b_256(ser_pk)[..20].to_vec()
    };
    let tx = gen_tx(
        &mut data_loader,
        SIGHASH_ALL_BIN.clone(),
        vec![pubkey_hash.into()],
    );
    let tx = {
        let tx_hash = rand_tx_hash();
        sign_tx_hash(tx, &privkey, tx_hash.as_ref())
    };
    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    let script_config = ScriptConfig::default();
    let verify_result = TransactionScriptsVerifier::new(&resolved_tx, &data_loader, &script_config)
        .verify(MAX_CYCLES);
    assert_eq!(verify_result, Err(ScriptError::ValidationFailure(-3)));
}

#[test]
fn test_super_long_witness() {
    let mut data_loader = DummyDataLoader::new();
    let key_gen = Generator::new();
    let privkey = key_gen.random_privkey();
    let pubkey = privkey.pubkey().expect("pubkey");
    // compute pubkey hash
    let pubkey_hash = {
        let ser_pk = pubkey.serialize();
        ckb_hash::blake2b_256(ser_pk)[..20].to_vec()
    };
    let tx = gen_tx(
        &mut data_loader,
        SIGHASH_ALL_BIN.clone(),
        vec![pubkey_hash.into()],
    );

    let mut buffer: Vec<u8> = vec![];
    buffer.resize(40000, 1);
    let super_long_message = Bytes::from(&buffer[..]);

    let mut blake2b = ckb_hash::new_blake2b();
    let mut message = [0u8; 32];
    blake2b.update(&tx.hash()[..]);
    blake2b.update(&super_long_message[..]);
    blake2b.finalize(&mut message);
    let message = H256::from(message);
    let sig = privkey.sign_recoverable(&message).expect("sign");
    let tx = TransactionBuilder::from_transaction(tx)
        .witness(vec![Bytes::from(sig.serialize()), super_long_message])
        .build();

    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    let script_config = ScriptConfig::default();
    let verify_result = TransactionScriptsVerifier::new(&resolved_tx, &data_loader, &script_config)
        .verify(MAX_CYCLES);
    assert_eq!(verify_result, Err(ScriptError::ValidationFailure(-12)));
}
