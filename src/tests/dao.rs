use super::{sign_tx, DummyDataLoader, DAO_BIN, MAX_CYCLES, SECP256K1_DATA_BIN, SIGHASH_ALL_BIN};
use byteorder::{ByteOrder, LittleEndian};
use ckb_crypto::secp::{Generator, Privkey};
use ckb_dao_utils::pack_dao_data;
use ckb_script::{ScriptConfig, ScriptError, TransactionScriptsVerifier};
use ckb_types::{
    bytes::Bytes,
    core::{
        cell::{CellMeta, CellMetaBuilder, ResolvedTransaction},
        BlockNumber, Capacity, HeaderBuilder, HeaderView, ScriptHashType, TransactionBuilder,
        TransactionInfo, TransactionView,
    },
    packed::{Byte32, CellDep, CellInput, CellOutput, OutPoint, Script},
    prelude::*,
    H256,
};
use rand::{thread_rng, Rng};

fn cell_output_with_only_capacity(shannons: u64) -> CellOutput {
    CellOutput::new_builder()
        .capacity(Capacity::shannons(shannons).pack())
        .build()
}

fn script_cell(script_data: &Bytes) -> (CellOutput, OutPoint) {
    let tx_hash = {
        let mut rng = thread_rng();
        let mut buf = [0u8; 32];
        rng.fill(&mut buf);
        H256::from(&buf)
    };
    let out_point = OutPoint::new(tx_hash, 0);

    let cell = CellOutput::new_builder()
        .capacity(
            Capacity::bytes(script_data.len())
                .expect("script capacity")
                .pack(),
        )
        .build();

    (cell, out_point)
}

fn secp_code_hash() -> Byte32 {
    CellOutput::calc_data_hash(&SIGHASH_ALL_BIN).pack()
}

fn dao_code_hash() -> Byte32 {
    CellOutput::calc_data_hash(&DAO_BIN).pack()
}

fn gen_dao_cell(
    dummy: &mut DummyDataLoader,
    capacity: Capacity,
    lock_args: Vec<Bytes>,
) -> (CellOutput, OutPoint) {
    let tx_hash = {
        let mut rng = thread_rng();
        let mut buf = [0u8; 32];
        rng.fill(&mut buf);
        H256::from(&buf)
    };
    let out_point = OutPoint::new(tx_hash, 0);

    let lock = Script::new_builder()
        .args(lock_args.pack())
        .code_hash(secp_code_hash())
        .hash_type(ScriptHashType::Data.pack())
        .build();
    let type_ = Script::new_builder()
        .args(vec![].pack())
        .code_hash(dao_code_hash())
        .hash_type(ScriptHashType::Data.pack())
        .build();
    let cell = CellOutput::new_builder()
        .capacity(capacity.pack())
        .lock(lock)
        .type_(Some(type_).pack())
        .build();
    dummy
        .cells
        .insert(out_point.clone(), (cell.clone(), Bytes::new()));

    (cell, out_point)
}

fn gen_header(number: BlockNumber, ar: u64) -> HeaderView {
    HeaderBuilder::default()
        .number(number.pack())
        .dao(pack_dao_data(ar, Capacity::shannons(0), Capacity::shannons(0)).pack())
        .build()
}

fn gen_lock() -> (Privkey, Vec<Bytes>) {
    let privkey = Generator::random_privkey();
    let pubkey = privkey.pubkey().expect("pubkey");
    // compute pubkey hash
    let pubkey_hash = {
        let ser_pk = pubkey.serialize();
        ckb_hash::blake2b_256(ser_pk)[..20].to_vec()
    };
    let lock_args = vec![pubkey_hash.into()];
    (privkey, lock_args)
}

fn complete_tx(
    dummy: &mut DummyDataLoader,
    builder: TransactionBuilder,
) -> (TransactionView, Vec<CellMeta>) {
    let (secp_cell, secp_out_point) = script_cell(&SIGHASH_ALL_BIN);
    let (secp_data_cell, secp_data_out_point) = script_cell(&SECP256K1_DATA_BIN);
    let (dao_cell, dao_out_point) = script_cell(&DAO_BIN);

    let secp_cell_meta =
        CellMetaBuilder::from_cell_output(secp_cell.clone(), SIGHASH_ALL_BIN.clone())
            .out_point(secp_out_point.clone())
            .build();
    let secp_data_cell_meta =
        CellMetaBuilder::from_cell_output(secp_data_cell.clone(), SECP256K1_DATA_BIN.clone())
            .out_point(secp_data_out_point.clone())
            .build();
    let dao_cell_meta = CellMetaBuilder::from_cell_output(dao_cell.clone(), DAO_BIN.clone())
        .out_point(dao_out_point.clone())
        .build();

    dummy
        .cells
        .insert(secp_out_point.clone(), (secp_cell, SIGHASH_ALL_BIN.clone()));
    dummy.cells.insert(
        secp_data_out_point.clone(),
        (secp_data_cell, SECP256K1_DATA_BIN.clone()),
    );
    dummy
        .cells
        .insert(dao_out_point.clone(), (dao_cell, DAO_BIN.clone()));

    let tx = builder
        .cell_dep(CellDep::new(secp_out_point, false))
        .cell_dep(CellDep::new(secp_data_out_point, false))
        .cell_dep(CellDep::new(dao_out_point, false))
        .build();

    let mut resolved_cell_deps = vec![];
    resolved_cell_deps.push(secp_cell_meta);
    resolved_cell_deps.push(secp_data_cell_meta);
    resolved_cell_deps.push(dao_cell_meta);

    (tx, resolved_cell_deps)
}

#[test]
fn test_dao_single_cell() {
    let mut data_loader = DummyDataLoader::new();
    let (privkey, lock_args) = gen_lock();

    let deposit_header = gen_header(1000, 10000000);
    let withdraw_header = gen_header(2000, 10001000);
    let (cell, previous_out_point) = gen_dao_cell(
        &mut data_loader,
        Capacity::shannons(123456780000),
        lock_args,
    );

    data_loader
        .headers
        .insert(deposit_header.hash(), deposit_header.clone());
    data_loader
        .headers
        .insert(withdraw_header.hash(), withdraw_header.clone());

    let input_cell_meta = CellMetaBuilder::from_cell_output(cell, Bytes::new())
        .out_point(previous_out_point.clone())
        .transaction_info(TransactionInfo {
            block_hash: deposit_header.hash().unpack(),
            block_number: deposit_header.number(),
            block_epoch: 100,
            index: 0,
        })
        .build();

    let resolved_inputs = vec![input_cell_meta];
    let mut resolved_cell_deps = vec![];

    let mut b = [0; 8];
    LittleEndian::write_u64(&mut b, 0);
    let witness = vec![Bytes::from(&b[..]).pack()];
    let builder = TransactionBuilder::default()
        .input(CellInput::new(previous_out_point, 2011))
        .output(cell_output_with_only_capacity(123468045678))
        .output_data(Bytes::new().pack())
        .header_dep(withdraw_header.hash())
        .header_dep(deposit_header.hash())
        .witness(witness.pack());
    let (tx, mut resolved_cell_deps2) = complete_tx(&mut data_loader, builder);
    let tx = sign_tx(tx, &privkey);
    for dep in resolved_cell_deps2.drain(..) {
        resolved_cell_deps.push(dep);
    }
    let rtx = ResolvedTransaction {
        transaction: &tx,
        resolved_inputs,
        resolved_cell_deps,
        resolved_dep_groups: vec![],
    };

    let script_config = ScriptConfig::default();
    let verify_result =
        TransactionScriptsVerifier::new(&rtx, &data_loader, &script_config).verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_dao_single_cell_with_fees() {
    let mut data_loader = DummyDataLoader::new();
    let (privkey, lock_args) = gen_lock();

    let deposit_header = gen_header(1000, 10000000);
    let withdraw_header = gen_header(2000, 10001000);
    let (cell, previous_out_point) = gen_dao_cell(
        &mut data_loader,
        Capacity::shannons(123456780000),
        lock_args,
    );

    data_loader
        .headers
        .insert(deposit_header.hash(), deposit_header.clone());
    data_loader
        .headers
        .insert(withdraw_header.hash(), withdraw_header.clone());

    let input_cell_meta = CellMetaBuilder::from_cell_output(cell, Bytes::new())
        .out_point(previous_out_point.clone())
        .transaction_info(TransactionInfo {
            block_hash: deposit_header.hash().unpack(),
            block_number: deposit_header.number(),
            block_epoch: 100,
            index: 0,
        })
        .build();

    let resolved_inputs = vec![input_cell_meta];
    let mut resolved_cell_deps = vec![];

    let mut b = [0; 8];
    LittleEndian::write_u64(&mut b, 0);
    let witness = vec![Bytes::from(&b[..]).pack()];
    let builder = TransactionBuilder::default()
        .input(CellInput::new(previous_out_point, 2011))
        .output(cell_output_with_only_capacity(123458045678))
        .output_data(Bytes::new().pack())
        .header_dep(withdraw_header.hash())
        .header_dep(deposit_header.hash())
        .witness(witness.pack());
    let (tx, mut resolved_cell_deps2) = complete_tx(&mut data_loader, builder);
    let tx = sign_tx(tx, &privkey);
    for dep in resolved_cell_deps2.drain(..) {
        resolved_cell_deps.push(dep);
    }
    let rtx = ResolvedTransaction {
        transaction: &tx,
        resolved_inputs,
        resolved_cell_deps,
        resolved_dep_groups: vec![],
    };

    let script_config = ScriptConfig::default();
    let verify_result =
        TransactionScriptsVerifier::new(&rtx, &data_loader, &script_config).verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_dao_single_cell_with_dao_output_cell() {
    let mut data_loader = DummyDataLoader::new();
    let (privkey, lock_args) = gen_lock();

    let deposit_header = gen_header(1000, 10000000);
    let withdraw_header = gen_header(2000, 10001000);
    let (cell, previous_out_point) = gen_dao_cell(
        &mut data_loader,
        Capacity::shannons(123456780000),
        lock_args,
    );

    data_loader
        .headers
        .insert(deposit_header.hash(), deposit_header.clone());
    data_loader
        .headers
        .insert(withdraw_header.hash(), withdraw_header.clone());

    let input_cell_meta = CellMetaBuilder::from_cell_output(cell, Bytes::new())
        .out_point(previous_out_point.clone())
        .transaction_info(TransactionInfo {
            block_hash: deposit_header.hash().unpack(),
            block_number: deposit_header.number(),
            block_epoch: 100,
            index: 0,
        })
        .build();

    let resolved_inputs = vec![input_cell_meta];
    let mut resolved_cell_deps = vec![];

    let mut b = [0; 8];
    LittleEndian::write_u64(&mut b, 0);
    let witness = vec![Bytes::from(&b[..]).pack()];
    let type_ = Script::new_builder()
        .args(vec![].pack())
        .code_hash(dao_code_hash())
        .hash_type(ScriptHashType::Data.pack())
        .build();
    let builder = TransactionBuilder::default()
        .input(CellInput::new(previous_out_point, 2011))
        .output(
            cell_output_with_only_capacity(123468045678)
                .as_builder()
                .type_(Some(type_).pack())
                .build(),
        )
        .output_data(Bytes::new().pack())
        .header_dep(withdraw_header.hash())
        .header_dep(deposit_header.hash())
        .witness(witness.pack());
    let (tx, mut resolved_cell_deps2) = complete_tx(&mut data_loader, builder);
    let tx = sign_tx(tx, &privkey);
    for dep in resolved_cell_deps2.drain(..) {
        resolved_cell_deps.push(dep);
    }
    let rtx = ResolvedTransaction {
        transaction: &tx,
        resolved_inputs,
        resolved_cell_deps,
        resolved_dep_groups: vec![],
    };

    let script_config = ScriptConfig::default();
    let verify_result =
        TransactionScriptsVerifier::new(&rtx, &data_loader, &script_config).verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_dao_multiple_cells() {
    let mut data_loader = DummyDataLoader::new();
    let (privkey, lock_args) = gen_lock();

    let deposit_header = gen_header(1000, 10000000);
    let deposit_header2 = gen_header(1010, 10000010);
    let withdraw_header = gen_header(2000, 10001000);
    let withdraw_header2 = gen_header(2050, 10001050);
    let (cell, previous_out_point) = gen_dao_cell(
        &mut data_loader,
        Capacity::shannons(123456780000),
        lock_args.clone(),
    );
    let (cell2, previous_out_point2) = gen_dao_cell(
        &mut data_loader,
        Capacity::shannons(123456781000),
        lock_args,
    );

    data_loader
        .headers
        .insert(deposit_header.hash(), deposit_header.clone());
    data_loader
        .headers
        .insert(deposit_header2.hash(), deposit_header2.clone());
    data_loader
        .headers
        .insert(withdraw_header.hash(), withdraw_header.clone());
    data_loader
        .headers
        .insert(withdraw_header2.hash(), withdraw_header2.clone());

    let input_cell_meta = CellMetaBuilder::from_cell_output(cell, Bytes::new())
        .out_point(previous_out_point.clone())
        .transaction_info(TransactionInfo {
            block_hash: deposit_header.hash().unpack(),
            block_number: deposit_header.number(),
            block_epoch: 100,
            index: 0,
        })
        .build();
    let input_cell_meta2 = CellMetaBuilder::from_cell_output(cell2, Bytes::new())
        .out_point(previous_out_point2.clone())
        .transaction_info(TransactionInfo {
            block_hash: deposit_header2.hash().unpack(),
            block_number: deposit_header2.number(),
            block_epoch: 100,
            index: 0,
        })
        .build();

    let resolved_inputs = vec![input_cell_meta, input_cell_meta2];
    let mut resolved_cell_deps = vec![];

    let mut b = [0; 8];
    LittleEndian::write_u64(&mut b, 0);
    let mut b2 = [0; 8];
    LittleEndian::write_u64(&mut b2, 1);
    let builder = TransactionBuilder::default()
        .input(CellInput::new(previous_out_point, 2011))
        .input(CellInput::new(previous_out_point2, 2061))
        .output(cell_output_with_only_capacity(123468185678))
        .output(cell_output_with_only_capacity(123468642893))
        .outputs_data(vec![Bytes::new(); 2].pack())
        .header_dep(withdraw_header.hash())
        .header_dep(withdraw_header2.hash())
        .header_dep(deposit_header.hash())
        .header_dep(deposit_header2.hash())
        .witness(vec![Bytes::from(&b[..]).pack()].pack())
        .witness(vec![Bytes::from(&b2[..]).pack()].pack());
    let (tx, mut resolved_cell_deps2) = complete_tx(&mut data_loader, builder);
    let tx = sign_tx(tx, &privkey);
    for dep in resolved_cell_deps2.drain(..) {
        resolved_cell_deps.push(dep);
    }
    let rtx = ResolvedTransaction {
        transaction: &tx,
        resolved_inputs,
        resolved_cell_deps,
        resolved_dep_groups: vec![],
    };

    let script_config = ScriptConfig::default();
    let verify_result =
        TransactionScriptsVerifier::new(&rtx, &data_loader, &script_config).verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_dao_missing_deposit_header() {
    let mut data_loader = DummyDataLoader::new();
    let (privkey, lock_args) = gen_lock();

    let deposit_header = gen_header(1000, 10000000);
    let withdraw_header = gen_header(2000, 10001000);
    let (cell, previous_out_point) = gen_dao_cell(
        &mut data_loader,
        Capacity::shannons(123456780000),
        lock_args,
    );
    data_loader
        .headers
        .insert(withdraw_header.hash(), withdraw_header.clone());

    let cell_out_point = previous_out_point.clone();
    let previous_out_point = OutPoint::new_builder()
        .tx_hash(cell_out_point.tx_hash())
        .index(cell_out_point.index())
        .build();

    let input_cell_meta = CellMetaBuilder::from_cell_output(cell, Bytes::new())
        .out_point(previous_out_point.clone())
        .transaction_info(TransactionInfo {
            block_hash: deposit_header.hash().unpack(),
            block_number: deposit_header.number(),
            block_epoch: 100,
            index: 0,
        })
        .build();

    let resolved_inputs = vec![input_cell_meta];
    let mut resolved_cell_deps = vec![];

    let mut b = [0; 8];
    LittleEndian::write_u64(&mut b, 0);
    let witness = vec![Bytes::from(&b[..]).pack()];
    let builder = TransactionBuilder::default()
        .input(CellInput::new(previous_out_point, 2011))
        .output(cell_output_with_only_capacity(123468045678))
        .output_data(Bytes::new().pack())
        .header_dep(withdraw_header.hash())
        .header_dep(deposit_header.hash())
        .witness(witness.pack());
    let (tx, mut resolved_cell_deps2) = complete_tx(&mut data_loader, builder);
    let tx = sign_tx(tx, &privkey);
    for dep in resolved_cell_deps2.drain(..) {
        resolved_cell_deps.push(dep);
    }
    let rtx = ResolvedTransaction {
        transaction: &tx,
        resolved_inputs,
        resolved_cell_deps,
        resolved_dep_groups: vec![],
    };

    let script_config = ScriptConfig::default();
    let verify_result =
        TransactionScriptsVerifier::new(&rtx, &data_loader, &script_config).verify(MAX_CYCLES);
    assert_eq!(verify_result, Err(ScriptError::ValidationFailure(2)));
}

#[test]
fn test_dao_missing_withdraw_header() {
    let mut data_loader = DummyDataLoader::new();
    let (privkey, lock_args) = gen_lock();

    let deposit_header = gen_header(1000, 10000000);
    let (cell, previous_out_point) = gen_dao_cell(
        &mut data_loader,
        Capacity::shannons(123456780000),
        lock_args,
    );

    data_loader
        .headers
        .insert(deposit_header.hash(), deposit_header.clone());

    let input_cell_meta = CellMetaBuilder::from_cell_output(cell, Bytes::new())
        .out_point(previous_out_point.clone())
        .transaction_info(TransactionInfo {
            block_hash: deposit_header.hash().unpack(),
            block_number: deposit_header.number(),
            block_epoch: 100,
            index: 0,
        })
        .build();

    let resolved_inputs = vec![input_cell_meta];
    let mut resolved_cell_deps = vec![];

    let mut b = [0; 8];
    LittleEndian::write_u64(&mut b, 1);
    let witness = vec![Bytes::from(&b[..]).pack()];
    let builder = TransactionBuilder::default()
        .input(CellInput::new(previous_out_point, 2011))
        .output(cell_output_with_only_capacity(123468045678))
        .output_data(Bytes::new().pack())
        .header_dep(deposit_header.hash())
        .witness(witness.pack());
    let (tx, mut resolved_cell_deps2) = complete_tx(&mut data_loader, builder);
    let tx = sign_tx(tx, &privkey);
    for dep in resolved_cell_deps2.drain(..) {
        resolved_cell_deps.push(dep);
    }
    let rtx = ResolvedTransaction {
        transaction: &tx,
        resolved_inputs,
        resolved_cell_deps,
        resolved_dep_groups: vec![],
    };

    let script_config = ScriptConfig::default();
    let verify_result =
        TransactionScriptsVerifier::new(&rtx, &data_loader, &script_config).verify(MAX_CYCLES);
    assert_eq!(verify_result, Err(ScriptError::ValidationFailure(1)));
}

#[test]
fn test_dao_missing_invalid_withdraw_header() {
    let mut data_loader = DummyDataLoader::new();
    let (privkey, lock_args) = gen_lock();

    let deposit_header = gen_header(1000, 10000000);
    let withdraw_header = gen_header(999, 10000000);
    let (cell, previous_out_point) = gen_dao_cell(
        &mut data_loader,
        Capacity::shannons(123456780000),
        lock_args,
    );

    data_loader
        .headers
        .insert(deposit_header.hash(), deposit_header.clone());
    data_loader
        .headers
        .insert(withdraw_header.hash(), withdraw_header.clone());

    let input_cell_meta = CellMetaBuilder::from_cell_output(cell, Bytes::new())
        .out_point(previous_out_point.clone())
        .transaction_info(TransactionInfo {
            block_hash: deposit_header.hash().unpack(),
            block_number: deposit_header.number(),
            block_epoch: 100,
            index: 0,
        })
        .build();

    let resolved_inputs = vec![input_cell_meta];
    let mut resolved_cell_deps = vec![];

    let mut b = [0; 8];
    LittleEndian::write_u64(&mut b, 0);
    let witness = vec![Bytes::from(&b[..]).pack()];
    let builder = TransactionBuilder::default()
        .input(CellInput::new(previous_out_point, 2011))
        .output(cell_output_with_only_capacity(123468045678))
        .output_data(Bytes::new().pack())
        .header_dep(withdraw_header.hash())
        .header_dep(deposit_header.hash())
        .witness(witness.pack());
    let (tx, mut resolved_cell_deps2) = complete_tx(&mut data_loader, builder);
    let tx = sign_tx(tx, &privkey);
    for dep in resolved_cell_deps2.drain(..) {
        resolved_cell_deps.push(dep);
    }
    let rtx = ResolvedTransaction {
        transaction: &tx,
        resolved_inputs,
        resolved_cell_deps,
        resolved_dep_groups: vec![],
    };

    let script_config = ScriptConfig::default();
    let verify_result =
        TransactionScriptsVerifier::new(&rtx, &data_loader, &script_config).verify(MAX_CYCLES);
    assert_eq!(verify_result, Err(ScriptError::ValidationFailure(-14)));
}

#[test]
fn test_dao_missing_invalid_since() {
    let mut data_loader = DummyDataLoader::new();
    let (privkey, lock_args) = gen_lock();

    let deposit_header = gen_header(1000, 10000000);
    let withdraw_header = gen_header(2000, 10001000);
    let (cell, previous_out_point) = gen_dao_cell(
        &mut data_loader,
        Capacity::shannons(123456780000),
        lock_args,
    );

    data_loader
        .headers
        .insert(deposit_header.hash(), deposit_header.clone());
    data_loader
        .headers
        .insert(withdraw_header.hash(), withdraw_header.clone());

    let input_cell_meta = CellMetaBuilder::from_cell_output(cell, Bytes::new())
        .out_point(previous_out_point.clone())
        .transaction_info(TransactionInfo {
            block_hash: deposit_header.hash().unpack(),
            block_number: deposit_header.number(),
            block_epoch: 100,
            index: 0,
        })
        .build();

    let resolved_inputs = vec![input_cell_meta];
    let mut resolved_cell_deps = vec![];

    let mut b = [0; 8];
    LittleEndian::write_u64(&mut b, 0);
    let witness = vec![Bytes::from(&b[..]).pack()];
    let builder = TransactionBuilder::default()
        .input(CellInput::new(previous_out_point, 1900))
        .output(cell_output_with_only_capacity(123468045678))
        .output_data(Bytes::new().pack())
        .header_dep(withdraw_header.hash())
        .header_dep(deposit_header.hash())
        .witness(witness.pack());
    let (tx, mut resolved_cell_deps2) = complete_tx(&mut data_loader, builder);
    let tx = sign_tx(tx, &privkey);
    for dep in resolved_cell_deps2.drain(..) {
        resolved_cell_deps.push(dep);
    }
    let rtx = ResolvedTransaction {
        transaction: &tx,
        resolved_inputs,
        resolved_cell_deps,
        resolved_dep_groups: vec![],
    };

    let script_config = ScriptConfig::default();
    let verify_result =
        TransactionScriptsVerifier::new(&rtx, &data_loader, &script_config).verify(MAX_CYCLES);
    assert_eq!(verify_result, Err(ScriptError::ValidationFailure(-14)));
}

#[test]
fn test_dao_invalid_withdraw_amount() {
    let mut data_loader = DummyDataLoader::new();
    let (privkey, lock_args) = gen_lock();

    let deposit_header = gen_header(1000, 10000000);
    let withdraw_header = gen_header(2000, 10001000);
    let (cell, previous_out_point) = gen_dao_cell(
        &mut data_loader,
        Capacity::shannons(123456780000),
        lock_args,
    );

    data_loader
        .headers
        .insert(deposit_header.hash(), deposit_header.clone());
    data_loader
        .headers
        .insert(withdraw_header.hash(), withdraw_header.clone());

    let input_cell_meta = CellMetaBuilder::from_cell_output(cell, Bytes::new())
        .out_point(previous_out_point.clone())
        .transaction_info(TransactionInfo {
            block_hash: deposit_header.hash().unpack(),
            block_number: deposit_header.number(),
            block_epoch: 100,
            index: 0,
        })
        .build();

    let resolved_inputs = vec![input_cell_meta];
    let mut resolved_cell_deps = vec![];

    let mut b = [0; 8];
    LittleEndian::write_u64(&mut b, 0);
    let witness = vec![Bytes::from(&b[..]).pack()];
    let builder = TransactionBuilder::default()
        .input(CellInput::new(previous_out_point, 2011))
        .output(cell_output_with_only_capacity(123488045678))
        .output_data(Bytes::new().pack())
        .header_dep(withdraw_header.hash())
        .header_dep(deposit_header.hash())
        .witness(witness.pack());
    let (tx, mut resolved_cell_deps2) = complete_tx(&mut data_loader, builder);
    let tx = sign_tx(tx, &privkey);
    for dep in resolved_cell_deps2.drain(..) {
        resolved_cell_deps.push(dep);
    }
    let rtx = ResolvedTransaction {
        transaction: &tx,
        resolved_inputs,
        resolved_cell_deps,
        resolved_dep_groups: vec![],
    };

    let script_config = ScriptConfig::default();
    let verify_result =
        TransactionScriptsVerifier::new(&rtx, &data_loader, &script_config).verify(MAX_CYCLES);
    assert_eq!(verify_result, Err(ScriptError::ValidationFailure(-15)));
}
