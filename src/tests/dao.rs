use super::{sign_tx, DummyDataLoader, DAO_BIN, MAX_CYCLES, SIGHASH_ALL_BIN};
use byteorder::{ByteOrder, LittleEndian};
use ckb_core::{
    cell::{CellMetaBuilder, ResolvedOutPoint, ResolvedTransaction},
    header::{Header, HeaderBuilder},
    script::{Script, ScriptHashType},
    transaction::{CellInput, CellOutput, OutPoint, Transaction, TransactionBuilder},
    BlockNumber, Bytes, Capacity,
};
use ckb_crypto::secp::{Generator, Privkey};
use ckb_dao_utils::pack_dao_data;
use ckb_script::{ScriptConfig, ScriptError, TransactionScriptsVerifier};
use numext_fixed_hash::H256;
use rand::{thread_rng, Rng};

fn script_cell(script_data: &Bytes) -> (CellOutput, OutPoint) {
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

fn secp_code_hash() -> H256 {
    let (cell, _) = script_cell(&SIGHASH_ALL_BIN);
    cell.data_hash().to_owned()
}

fn dao_code_hash() -> H256 {
    let (cell, _) = script_cell(&DAO_BIN);
    cell.data_hash().to_owned()
}

fn gen_dao_cell(
    dummy: &mut DummyDataLoader,
    capacity: Capacity,
    header: &Header,
    lock_args: Vec<Bytes>,
) -> (CellOutput, OutPoint) {
    let tx_hash = {
        let mut rng = thread_rng();
        let mut buf = [0u8; 32];
        rng.fill(&mut buf);
        H256::from(&buf)
    };
    let out_point = OutPoint::new(header.hash().clone(), tx_hash, 0);

    let cell = CellOutput::new(
        capacity,
        H256::zero(),
        Script::new(lock_args, secp_code_hash(), ScriptHashType::Data),
        Some(Script::new(vec![], dao_code_hash(), ScriptHashType::Data)),
    );
    dummy.cells.insert(
        out_point.clone().cell.unwrap(),
        (cell.clone(), Bytes::new()),
    );

    (cell, out_point)
}

fn gen_header(number: BlockNumber, ar: u64) -> Header {
    HeaderBuilder::default()
        .number(number)
        .dao(pack_dao_data(
            ar,
            Capacity::shannons(0),
            Capacity::shannons(0),
        ))
        .build()
}

fn gen_lock() -> (Privkey, Vec<Bytes>) {
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

fn complete_tx(
    dummy: &mut DummyDataLoader,
    builder: TransactionBuilder,
) -> (Transaction, Vec<ResolvedOutPoint>) {
    let (secp_cell, secp_out_point) = script_cell(&SIGHASH_ALL_BIN);
    let (dao_cell, dao_out_point) = script_cell(&DAO_BIN);

    let secp_cell_meta =
        CellMetaBuilder::from_cell_output(secp_cell.clone(), SIGHASH_ALL_BIN.clone())
            .out_point(secp_out_point.clone().cell.unwrap())
            .build();
    let dao_cell_meta = CellMetaBuilder::from_cell_output(dao_cell.clone(), DAO_BIN.clone())
        .out_point(dao_out_point.clone().cell.unwrap())
        .build();

    dummy.cells.insert(
        secp_out_point.clone().cell.unwrap(),
        (secp_cell, SIGHASH_ALL_BIN.clone()),
    );
    dummy.cells.insert(
        dao_out_point.clone().cell.unwrap(),
        (dao_cell, DAO_BIN.clone()),
    );

    let tx = builder.dep(secp_out_point).dep(dao_out_point).build();

    let mut resolved_deps = vec![];
    resolved_deps.push(ResolvedOutPoint::cell_only(secp_cell_meta));
    resolved_deps.push(ResolvedOutPoint::cell_only(dao_cell_meta));

    (tx, resolved_deps)
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
        &deposit_header,
        lock_args,
    );

    let input_cell_meta = CellMetaBuilder::from_cell_output(cell, Bytes::new())
        .out_point(previous_out_point.clone().cell.unwrap())
        .build();

    let resolved_inputs = vec![ResolvedOutPoint::cell_and_header(
        input_cell_meta,
        deposit_header,
    )];
    let mut resolved_deps = vec![ResolvedOutPoint::header_only(withdraw_header.clone())];

    let mut b = [0; 8];
    LittleEndian::write_u64(&mut b, 0);
    let witness = vec![Bytes::from(&b[..])];
    let builder = TransactionBuilder::default()
        .input(CellInput::new(previous_out_point, 2011))
        .output(CellOutput::new(
            Capacity::shannons(123468045678),
            Default::default(),
            Default::default(),
            None,
        ))
        .output_data(Bytes::new())
        .dep(OutPoint::new_block_hash(withdraw_header.hash().clone()))
        .witness(witness);
    let (tx, mut resolved_deps2) = complete_tx(&mut data_loader, builder);
    let tx = sign_tx(tx, &privkey);
    for dep in resolved_deps2.drain(..) {
        resolved_deps.push(dep);
    }
    let rtx = ResolvedTransaction {
        transaction: &tx,
        resolved_inputs,
        resolved_deps,
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
        &deposit_header,
        lock_args,
    );

    let input_cell_meta = CellMetaBuilder::from_cell_output(cell, Bytes::new())
        .out_point(previous_out_point.clone().cell.unwrap())
        .build();

    let resolved_inputs = vec![ResolvedOutPoint::cell_and_header(
        input_cell_meta,
        deposit_header,
    )];
    let mut resolved_deps = vec![ResolvedOutPoint::header_only(withdraw_header.clone())];

    let mut b = [0; 8];
    LittleEndian::write_u64(&mut b, 0);
    let witness = vec![Bytes::from(&b[..])];
    let builder = TransactionBuilder::default()
        .input(CellInput::new(previous_out_point, 2011))
        .output(CellOutput::new(
            Capacity::shannons(123458045678),
            Default::default(),
            Default::default(),
            None,
        ))
        .output_data(Bytes::new())
        .dep(OutPoint::new_block_hash(withdraw_header.hash().clone()))
        .witness(witness);
    let (tx, mut resolved_deps2) = complete_tx(&mut data_loader, builder);
    let tx = sign_tx(tx, &privkey);
    for dep in resolved_deps2.drain(..) {
        resolved_deps.push(dep);
    }
    let rtx = ResolvedTransaction {
        transaction: &tx,
        resolved_inputs,
        resolved_deps,
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
        &deposit_header,
        lock_args,
    );

    let input_cell_meta = CellMetaBuilder::from_cell_output(cell, Bytes::new())
        .out_point(previous_out_point.clone().cell.unwrap())
        .build();

    let resolved_inputs = vec![ResolvedOutPoint::cell_and_header(
        input_cell_meta,
        deposit_header,
    )];
    let mut resolved_deps = vec![ResolvedOutPoint::header_only(withdraw_header.clone())];

    let mut b = [0; 8];
    LittleEndian::write_u64(&mut b, 0);
    let witness = vec![Bytes::from(&b[..])];
    let builder = TransactionBuilder::default()
        .input(CellInput::new(previous_out_point, 2011))
        .output(CellOutput::new(
            Capacity::shannons(123468045678),
            Default::default(),
            Default::default(),
            Some(Script::new(vec![], dao_code_hash(), ScriptHashType::Data)),
        ))
        .output_data(Bytes::new())
        .dep(OutPoint::new_block_hash(withdraw_header.hash().clone()))
        .witness(witness);
    let (tx, mut resolved_deps2) = complete_tx(&mut data_loader, builder);
    let tx = sign_tx(tx, &privkey);
    for dep in resolved_deps2.drain(..) {
        resolved_deps.push(dep);
    }
    let rtx = ResolvedTransaction {
        transaction: &tx,
        resolved_inputs,
        resolved_deps,
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
        &deposit_header,
        lock_args.clone(),
    );
    let (cell2, previous_out_point2) = gen_dao_cell(
        &mut data_loader,
        Capacity::shannons(123456781000),
        &deposit_header2,
        lock_args,
    );

    let input_cell_meta = CellMetaBuilder::from_cell_output(cell, Bytes::new())
        .out_point(previous_out_point.clone().cell.unwrap())
        .build();
    let input_cell_meta2 = CellMetaBuilder::from_cell_output(cell2, Bytes::new())
        .out_point(previous_out_point2.clone().cell.unwrap())
        .build();

    let resolved_inputs = vec![
        ResolvedOutPoint::cell_and_header(input_cell_meta, deposit_header),
        ResolvedOutPoint::cell_and_header(input_cell_meta2, deposit_header2),
    ];
    let mut resolved_deps = vec![
        ResolvedOutPoint::header_only(withdraw_header.clone()),
        ResolvedOutPoint::header_only(withdraw_header2.clone()),
    ];

    let mut b = [0; 8];
    LittleEndian::write_u64(&mut b, 0);
    let mut b2 = [0; 8];
    LittleEndian::write_u64(&mut b2, 1);
    let builder = TransactionBuilder::default()
        .input(CellInput::new(previous_out_point, 2011))
        .input(CellInput::new(previous_out_point2, 2061))
        .output(CellOutput::new(
            Capacity::shannons(123468185678),
            Default::default(),
            Default::default(),
            None,
        ))
        .output(CellOutput::new(
            Capacity::shannons(123468642893),
            Default::default(),
            Default::default(),
            None,
        ))
        .outputs_data(vec![Bytes::new(); 2])
        .dep(OutPoint::new_block_hash(withdraw_header.hash().clone()))
        .dep(OutPoint::new_block_hash(withdraw_header2.hash().clone()))
        .witness(vec![Bytes::from(&b[..])])
        .witness(vec![Bytes::from(&b2[..])]);
    let (tx, mut resolved_deps2) = complete_tx(&mut data_loader, builder);
    let tx = sign_tx(tx, &privkey);
    for dep in resolved_deps2.drain(..) {
        resolved_deps.push(dep);
    }
    let rtx = ResolvedTransaction {
        transaction: &tx,
        resolved_inputs,
        resolved_deps,
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
        &deposit_header,
        lock_args,
    );
    let cell_out_point = previous_out_point.clone().cell.unwrap();
    let previous_out_point = OutPoint::new_cell(cell_out_point.tx_hash, cell_out_point.index);

    let input_cell_meta = CellMetaBuilder::from_cell_output(cell, Bytes::new())
        .out_point(previous_out_point.clone().cell.unwrap())
        .build();

    let resolved_inputs = vec![ResolvedOutPoint::cell_only(input_cell_meta)];
    let mut resolved_deps = vec![ResolvedOutPoint::header_only(withdraw_header.clone())];

    let mut b = [0; 8];
    LittleEndian::write_u64(&mut b, 0);
    let witness = vec![Bytes::from(&b[..])];
    let builder = TransactionBuilder::default()
        .input(CellInput::new(previous_out_point, 2011))
        .output(CellOutput::new(
            Capacity::shannons(123468045678),
            Default::default(),
            Default::default(),
            None,
        ))
        .output_data(Bytes::new())
        .dep(OutPoint::new_block_hash(withdraw_header.hash().clone()))
        .witness(witness);
    let (tx, mut resolved_deps2) = complete_tx(&mut data_loader, builder);
    let tx = sign_tx(tx, &privkey);
    for dep in resolved_deps2.drain(..) {
        resolved_deps.push(dep);
    }
    let rtx = ResolvedTransaction {
        transaction: &tx,
        resolved_inputs,
        resolved_deps,
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
        &deposit_header,
        lock_args,
    );

    let input_cell_meta = CellMetaBuilder::from_cell_output(cell, Bytes::new())
        .out_point(previous_out_point.clone().cell.unwrap())
        .build();

    let resolved_inputs = vec![ResolvedOutPoint::cell_and_header(
        input_cell_meta,
        deposit_header,
    )];
    let mut resolved_deps = vec![];

    let mut b = [0; 8];
    LittleEndian::write_u64(&mut b, 0);
    let witness = vec![Bytes::from(&b[..])];
    let builder = TransactionBuilder::default()
        .input(CellInput::new(previous_out_point, 2011))
        .output(CellOutput::new(
            Capacity::shannons(123468045678),
            Default::default(),
            Default::default(),
            None,
        ))
        .output_data(Bytes::new())
        .witness(witness);
    let (tx, mut resolved_deps2) = complete_tx(&mut data_loader, builder);
    let tx = sign_tx(tx, &privkey);
    for dep in resolved_deps2.drain(..) {
        resolved_deps.push(dep);
    }
    let rtx = ResolvedTransaction {
        transaction: &tx,
        resolved_inputs,
        resolved_deps,
    };

    let script_config = ScriptConfig::default();
    let verify_result =
        TransactionScriptsVerifier::new(&rtx, &data_loader, &script_config).verify(MAX_CYCLES);
    assert_eq!(verify_result, Err(ScriptError::ValidationFailure(2)));
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
        &deposit_header,
        lock_args,
    );

    let input_cell_meta = CellMetaBuilder::from_cell_output(cell, Bytes::new())
        .out_point(previous_out_point.clone().cell.unwrap())
        .build();

    let resolved_inputs = vec![ResolvedOutPoint::cell_and_header(
        input_cell_meta,
        deposit_header,
    )];
    let mut resolved_deps = vec![ResolvedOutPoint::header_only(withdraw_header.clone())];

    let mut b = [0; 8];
    LittleEndian::write_u64(&mut b, 0);
    let witness = vec![Bytes::from(&b[..])];
    let builder = TransactionBuilder::default()
        .input(CellInput::new(previous_out_point, 2011))
        .output(CellOutput::new(
            Capacity::shannons(123468045678),
            Default::default(),
            Default::default(),
            None,
        ))
        .output_data(Bytes::new())
        .dep(OutPoint::new_block_hash(withdraw_header.hash().clone()))
        .witness(witness);
    let (tx, mut resolved_deps2) = complete_tx(&mut data_loader, builder);
    let tx = sign_tx(tx, &privkey);
    for dep in resolved_deps2.drain(..) {
        resolved_deps.push(dep);
    }
    let rtx = ResolvedTransaction {
        transaction: &tx,
        resolved_inputs,
        resolved_deps,
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
        &deposit_header,
        lock_args,
    );

    let input_cell_meta = CellMetaBuilder::from_cell_output(cell, Bytes::new())
        .out_point(previous_out_point.clone().cell.unwrap())
        .build();

    let resolved_inputs = vec![ResolvedOutPoint::cell_and_header(
        input_cell_meta,
        deposit_header,
    )];
    let mut resolved_deps = vec![ResolvedOutPoint::header_only(withdraw_header.clone())];

    let mut b = [0; 8];
    LittleEndian::write_u64(&mut b, 0);
    let witness = vec![Bytes::from(&b[..])];
    let builder = TransactionBuilder::default()
        .input(CellInput::new(previous_out_point, 1900))
        .output(CellOutput::new(
            Capacity::shannons(123468045678),
            Default::default(),
            Default::default(),
            None,
        ))
        .output_data(Bytes::new())
        .dep(OutPoint::new_block_hash(withdraw_header.hash().clone()))
        .witness(witness);
    let (tx, mut resolved_deps2) = complete_tx(&mut data_loader, builder);
    let tx = sign_tx(tx, &privkey);
    for dep in resolved_deps2.drain(..) {
        resolved_deps.push(dep);
    }
    let rtx = ResolvedTransaction {
        transaction: &tx,
        resolved_inputs,
        resolved_deps,
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
        &deposit_header,
        lock_args,
    );

    let input_cell_meta = CellMetaBuilder::from_cell_output(cell, Bytes::new())
        .out_point(previous_out_point.clone().cell.unwrap())
        .build();

    let resolved_inputs = vec![ResolvedOutPoint::cell_and_header(
        input_cell_meta,
        deposit_header,
    )];
    let mut resolved_deps = vec![ResolvedOutPoint::header_only(withdraw_header.clone())];

    let mut b = [0; 8];
    LittleEndian::write_u64(&mut b, 0);
    let witness = vec![Bytes::from(&b[..])];
    let builder = TransactionBuilder::default()
        .input(CellInput::new(previous_out_point, 2011))
        .output(CellOutput::new(
            Capacity::shannons(123488045678),
            Default::default(),
            Default::default(),
            None,
        ))
        .output_data(Bytes::new())
        .dep(OutPoint::new_block_hash(withdraw_header.hash().clone()))
        .witness(witness);
    let (tx, mut resolved_deps2) = complete_tx(&mut data_loader, builder);
    let tx = sign_tx(tx, &privkey);
    for dep in resolved_deps2.drain(..) {
        resolved_deps.push(dep);
    }
    let rtx = ResolvedTransaction {
        transaction: &tx,
        resolved_inputs,
        resolved_deps,
    };

    let script_config = ScriptConfig::default();
    let verify_result =
        TransactionScriptsVerifier::new(&rtx, &data_loader, &script_config).verify(MAX_CYCLES);
    assert_eq!(verify_result, Err(ScriptError::ValidationFailure(-15)));
}
