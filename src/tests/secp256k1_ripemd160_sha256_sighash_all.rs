use super::{DummyDataLoader, BITCOIN_P2PKH_BIN, MAX_CYCLES, SECP256K1_DATA_BIN};
use ckb_crypto::secp::{Generator, Privkey, Pubkey};
use ckb_script::{ScriptConfig, ScriptError, TransactionScriptsVerifier};
use ckb_types::{
    bytes::Bytes,
    core::{
        cell::{CellMetaBuilder, ResolvedTransaction},
        Capacity, ScriptHashType, TransactionBuilder, TransactionView,
    },
    h160, h256,
    packed::{CellDep, CellInput, CellOutput, OutPoint, Script, Witness},
    prelude::*,
    H160, H256,
};
use rand::{thread_rng, Rng};

fn gen_tx(
    dummy: &mut DummyDataLoader,
    script_data: Bytes,
    lock_args: Vec<Bytes>,
    extra_witness: Vec<Bytes>,
) -> TransactionView {
    let previous_tx_hash = {
        let mut rng = thread_rng();
        let mut buf = [0u8; 32];
        rng.fill(&mut buf);
        H256::from(&buf)
    };
    let previous_index = 0;
    let capacity = Capacity::shannons(42);
    let previous_out_point = OutPoint::new(previous_tx_hash, previous_index);
    let contract_tx_hash = {
        let mut rng = thread_rng();
        let mut buf = [0u8; 32];
        rng.fill(&mut buf);
        H256::from(&buf)
    };
    let contract_index = 0;
    let contract_out_point = OutPoint::new(contract_tx_hash.clone(), contract_index);
    // dep contract code
    let dep_cell = CellOutput::new_builder()
        .capacity(
            Capacity::bytes(script_data.len())
                .expect("script capacity")
                .pack(),
        )
        .build();
    let dep_cell_data_hash = CellOutput::calc_data_hash(&script_data).pack();
    dummy
        .cells
        .insert(contract_out_point.clone(), (dep_cell, script_data));
    // secp256k1 data
    let secp256k1_data_out_point = {
        let tx_hash = {
            let mut rng = thread_rng();
            let mut buf = [0u8; 32];
            rng.fill(&mut buf);
            H256::from(&buf)
        };
        OutPoint::new(tx_hash, 0)
    };
    let secp256k1_data_cell = CellOutput::new_builder()
        .capacity(
            Capacity::bytes(SECP256K1_DATA_BIN.len())
                .expect("data capacity")
                .pack(),
        )
        .build();
    dummy.cells.insert(
        secp256k1_data_out_point.clone(),
        (secp256k1_data_cell, SECP256K1_DATA_BIN.clone()),
    );
    // input unlock script
    let script = Script::new_builder()
        .args(lock_args.pack())
        .code_hash(dep_cell_data_hash)
        .hash_type(ScriptHashType::Data.pack())
        .build();
    let previous_output_cell = CellOutput::new_builder()
        .capacity(capacity.pack())
        .lock(script)
        .build();
    dummy.cells.insert(
        previous_out_point.clone(),
        (previous_output_cell, Bytes::new()),
    );
    TransactionBuilder::default()
        .input(CellInput::new(previous_out_point.clone(), 0))
        .witness(extra_witness.into_iter().map(|x| x.pack()).pack())
        .cell_dep(CellDep::new(contract_out_point, false))
        .cell_dep(CellDep::new(secp256k1_data_out_point, false))
        .output(CellOutput::new_builder().capacity(capacity.pack()).build())
        .output_data(Bytes::new().pack())
        .build()
}

// Special signature method, inconsistent with the default lock behavior,
// witness signature only sign transaction hash
pub fn sign_tx(tx: TransactionView, key: &Privkey) -> TransactionView {
    let tx_hash: H256 = tx.hash().unpack();
    let signed_witnesses: Vec<Witness> = tx
        .inputs()
        .into_iter()
        .enumerate()
        .map(|(i, _)| {
            let witness = tx.witnesses().get(i).unwrap_or_default();
            let sig = key.sign_recoverable(&tx_hash).expect("sign");
            let mut signed_witness = vec![Bytes::from(sig.serialize()).pack()];
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

fn build_resolved_tx<'a>(
    data_loader: &DummyDataLoader,
    tx: &'a TransactionView,
) -> ResolvedTransaction<'a> {
    let previous_out_point = tx
        .inputs()
        .get(0)
        .expect("should have at least one input")
        .previous_output();
    let resolved_cell_deps = tx
        .cell_deps()
        .into_iter()
        .map(|dep| {
            let deps_out_point = dep.clone();
            let (dep_output, dep_data) =
                data_loader.cells.get(&deps_out_point.out_point()).unwrap();
            CellMetaBuilder::from_cell_output(dep_output.to_owned(), dep_data.to_owned())
                .out_point(deps_out_point.out_point().clone())
                .build()
        })
        .collect();
    let (input_output, input_data) = data_loader.cells.get(&previous_out_point).unwrap();
    let input_cell =
        CellMetaBuilder::from_cell_output(input_output.to_owned(), input_data.to_owned())
            .out_point(previous_out_point)
            .build();
    ResolvedTransaction {
        transaction: tx,
        resolved_cell_deps,
        resolved_inputs: vec![input_cell],
        resolved_dep_groups: vec![],
    }
}

fn ripemd160(data: &[u8]) -> H160 {
    use ripemd160::{Digest, Ripemd160};
    let digest: [u8; 20] = Ripemd160::digest(data).into();
    H160::from(&digest)
}

fn sha256(data: &[u8]) -> H256 {
    use sha2::{Digest, Sha256};
    let digest: [u8; 32] = Sha256::digest(data).into();
    H256::from(&digest)
}

fn pubkey_uncompressed(pubkey: &Pubkey) -> Vec<u8> {
    let mut serialized = vec![4u8; 65];
    serialized[1..65].copy_from_slice(pubkey.as_ref());
    serialized
}

fn pubkey_compressed(pubkey: &Pubkey) -> Vec<u8> {
    pubkey.serialize()
}

fn pubkey_hash(serialized_pubkey: &[u8]) -> Vec<u8> {
    ripemd160(sha256(serialized_pubkey).as_bytes()).to_vec()
}

#[test]
fn test_rust_crypto() {
    assert_eq!(
        h160!("0x9c1185a5c5e9fc54612808977ee8f548b2258d31"),
        ripemd160(b"")
    );
    assert_eq!(
        h256!("0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        sha256(b"")
    );
}

#[test]
fn test_sighash_all_unlock() {
    let mut data_loader = DummyDataLoader::new();
    let key_gen = Generator::new();
    let privkey = key_gen.random_privkey();
    let pubkey = pubkey_compressed(&privkey.pubkey().expect("pubkey"));
    // compute pubkey hash
    let pubkey_hash = pubkey_hash(&pubkey);
    let tx = gen_tx(
        &mut data_loader,
        BITCOIN_P2PKH_BIN.clone(),
        vec![pubkey_hash.into()],
        vec![pubkey.into()],
    );
    let tx = sign_tx(tx, &privkey);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    let script_config = ScriptConfig::default();
    let verify_result = TransactionScriptsVerifier::new(&resolved_tx, &data_loader, &script_config)
        .verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_sighash_all_unlock_with_uncompressed_pubkey() {
    let mut data_loader = DummyDataLoader::new();
    let key_gen = Generator::new();
    let privkey = key_gen.random_privkey();
    let pubkey = pubkey_uncompressed(&privkey.pubkey().expect("pubkey"));
    let pubkey_hash = pubkey_hash(&pubkey);
    let tx = gen_tx(
        &mut data_loader,
        BITCOIN_P2PKH_BIN.clone(),
        vec![pubkey_hash.into()],
        vec![pubkey.into()],
    );
    let tx = sign_tx(tx, &privkey);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    let script_config = ScriptConfig::default();
    let verify_result = TransactionScriptsVerifier::new(&resolved_tx, &data_loader, &script_config)
        .verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_sighash_all_unlock_with_uncompressed_pubkey_and_non_recoverable_signature() {
    let mut data_loader = DummyDataLoader::new();
    let key_gen = Generator::new();
    let privkey = key_gen.random_privkey();
    let pubkey = pubkey_uncompressed(&privkey.pubkey().expect("pubkey"));
    let pubkey_hash = pubkey_hash(&pubkey);

    let tx = gen_tx(
        &mut data_loader,
        BITCOIN_P2PKH_BIN.clone(),
        vec![pubkey_hash.into()],
        vec![],
    );
    // Create non-recoverable signature
    let tx = {
        let tx_hash: H256 = tx.hash().unpack();
        let context = &ckb_crypto::secp::SECP256K1;
        let message = secp256k1::Message::from_slice(tx_hash.as_bytes()).unwrap();
        let privkey = secp256k1::key::SecretKey::from_slice(privkey.as_bytes()).unwrap();
        let signature = context.sign(&message, &privkey);
        let signature = Bytes::from(&signature.serialize_compact()[..]);
        let pubkey_bytes: Bytes = pubkey.into();

        tx.as_advanced_builder()
            .set_witnesses(vec![])
            .witness(vec![signature.pack(), pubkey_bytes.pack()].pack())
            .build()
    };

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
    let wrong_pubkey = pubkey_compressed(&wrong_privkey.pubkey().expect("pubkey"));
    let pubkey = pubkey_compressed(&privkey.pubkey().expect("pubkey"));
    let pubkey_hash = pubkey_hash(&pubkey);
    let tx = gen_tx(
        &mut data_loader,
        BITCOIN_P2PKH_BIN.clone(),
        vec![pubkey_hash.into()],
        vec![wrong_pubkey.into()],
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
    let pubkey = pubkey_compressed(&privkey.pubkey().expect("pubkey"));
    let pubkey_hash = pubkey_hash(&pubkey);
    let tx = gen_tx(
        &mut data_loader,
        BITCOIN_P2PKH_BIN.clone(),
        vec![pubkey_hash.into()],
        vec![pubkey.into()],
    );
    let tx = sign_tx(tx, &privkey);
    // Change tx hash
    let tx = tx.as_advanced_builder().output(Default::default()).build();

    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    let script_config = ScriptConfig::default();
    let verify_result = TransactionScriptsVerifier::new(&resolved_tx, &data_loader, &script_config)
        .verify(MAX_CYCLES);
    assert_eq!(verify_result, Err(ScriptError::ValidationFailure(-9)));
}

#[test]
fn test_super_long_witness() {
    let mut data_loader = DummyDataLoader::new();
    let key_gen = Generator::new();
    let privkey = key_gen.random_privkey();
    let pubkey = pubkey_compressed(&privkey.pubkey().expect("pubkey"));
    // compute pubkey hash
    let pubkey_hash = pubkey_hash(&pubkey);
    let tx = gen_tx(
        &mut data_loader,
        BITCOIN_P2PKH_BIN.clone(),
        vec![pubkey_hash.into()],
        vec![pubkey.into()],
    );
    let tx_hash: H256 = tx.hash().unpack();

    let mut buffer: Vec<u8> = vec![];
    buffer.resize(40000, 1);
    let super_long_message = Bytes::from(&buffer[..]);

    let sig = privkey.sign_recoverable(&tx_hash).expect("sign");
    let tx = tx
        .as_advanced_builder()
        .set_witnesses(vec![])
        .witness(
            vec![
                Bytes::from(sig.serialize()).pack(),
                super_long_message.pack(),
            ]
            .pack(),
        )
        .build();

    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    let script_config = ScriptConfig::default();
    let verify_result = TransactionScriptsVerifier::new(&resolved_tx, &data_loader, &script_config)
        .verify(MAX_CYCLES);
    assert_eq!(verify_result, Err(ScriptError::ValidationFailure(-12)));
}

#[test]
fn test_wrong_size_witness_args() {
    let mut data_loader = DummyDataLoader::new();
    let key_gen = Generator::new();
    let privkey = key_gen.random_privkey();
    let pubkey = pubkey_uncompressed(&privkey.pubkey().expect("pubkey"));
    let pubkey_hash = pubkey_hash(&pubkey);
    let raw_tx = gen_tx(
        &mut data_loader,
        BITCOIN_P2PKH_BIN.clone(),
        vec![pubkey_hash.into()],
        vec![pubkey.into()],
    );
    // witness more than 2 args
    let tx = sign_tx(raw_tx.clone(), &privkey);
    let other_witness = Bytes::from("1243").pack();
    let tx = tx
        .as_advanced_builder()
        .set_witnesses(vec![])
        .witness(
            vec![
                other_witness.clone(),
                other_witness.clone(),
                other_witness.clone(),
            ]
            .pack(),
        )
        .build();
    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    let script_config = ScriptConfig::default();
    let verify_result = TransactionScriptsVerifier::new(&resolved_tx, &data_loader, &script_config)
        .verify(MAX_CYCLES);

    assert_eq!(verify_result, Err(ScriptError::ValidationFailure(-2)));

    // witness less than 2 args
    let tx = sign_tx(raw_tx.clone(), &privkey);
    let tx = tx
        .as_advanced_builder()
        .set_witnesses(vec![])
        .witness(vec![other_witness.clone()].pack())
        .build();
    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    let script_config = ScriptConfig::default();
    let verify_result = TransactionScriptsVerifier::new(&resolved_tx, &data_loader, &script_config)
        .verify(MAX_CYCLES);

    assert_eq!(verify_result, Err(ScriptError::ValidationFailure(-2)));
}
