use super::{
    gen_lock, script_cell, secp_code_hash, sign_tx, type_id_code_hash, DummyDataLoader, MAX_CYCLES,
    SIGHASH_ALL_BIN, TYPE_ID_BIN,
};
use ckb_core::{
    capacity_bytes,
    cell::{CellMetaBuilder, ResolvedOutPoint, ResolvedTransaction},
    script::{Script, ScriptHashType},
    transaction::{CellInput, CellOutput, OutPoint, Transaction, TransactionBuilder},
    Bytes, Capacity,
};
use ckb_hash::blake2b_256;
use ckb_protocol::CellInput as FbsCellInput;
use ckb_script::{ScriptConfig, ScriptError, TransactionScriptsVerifier};
use flatbuffers::FlatBufferBuilder;
use numext_fixed_hash::H256;
use rand::{thread_rng, Rng};

fn gen_cell(
    dummy: &mut DummyDataLoader,
    capacity: Capacity,
    lock_args: Vec<Bytes>,
    type_id_args: Option<Vec<Bytes>>,
) -> (CellOutput, OutPoint, Bytes) {
    let tx_hash = {
        let mut rng = thread_rng();
        let mut buf = [0u8; 32];
        rng.fill(&mut buf);
        H256::from(&buf)
    };
    let out_point = OutPoint::new_cell(tx_hash, 0);

    let data = Bytes::default();
    let data_hash = (&blake2b_256(&data)).into();
    let cell = CellOutput::new(
        capacity,
        data_hash,
        Script::new(lock_args, secp_code_hash(), ScriptHashType::Data),
        type_id_args.map(|args| Script::new(args, type_id_code_hash(), ScriptHashType::Data)),
    );
    dummy.cells.insert(
        out_point.clone().cell.unwrap(),
        (cell.clone(), Bytes::new()),
    );

    (cell, out_point, data)
}

fn complete_tx(
    dummy: &mut DummyDataLoader,
    builder: TransactionBuilder,
) -> (Transaction, Vec<ResolvedOutPoint>) {
    let (secp_cell, secp_out_point) = script_cell(&SIGHASH_ALL_BIN);
    let (type_id_cell, type_id_out_point) = script_cell(&TYPE_ID_BIN);

    let secp_cell_meta =
        CellMetaBuilder::from_cell_output(secp_cell.clone(), SIGHASH_ALL_BIN.clone())
            .out_point(secp_out_point.clone().cell.unwrap())
            .build();
    let type_id_cell_meta =
        CellMetaBuilder::from_cell_output(type_id_cell.clone(), TYPE_ID_BIN.clone())
            .out_point(type_id_out_point.clone().cell.unwrap())
            .build();

    dummy.cells.insert(
        secp_out_point.clone().cell.unwrap(),
        (secp_cell, SIGHASH_ALL_BIN.clone()),
    );
    dummy.cells.insert(
        type_id_out_point.clone().cell.unwrap(),
        (type_id_cell, TYPE_ID_BIN.clone()),
    );

    let tx = builder.dep(secp_out_point).dep(type_id_out_point).build();

    let mut resolved_deps = vec![];
    resolved_deps.push(ResolvedOutPoint::cell_only(secp_cell_meta));
    resolved_deps.push(ResolvedOutPoint::cell_only(type_id_cell_meta));

    (tx, resolved_deps)
}

#[test]
fn test_type_id_one_in_one_out() {
    let mut data_loader = DummyDataLoader::new();
    let (privkey, lock_args) = gen_lock();

    let type_id_args = {
        let mut rng = thread_rng();
        let mut buf = [0u8; 32];
        rng.fill(&mut buf);
        vec![Bytes::from(&buf[..])]
    };

    let (input_cell, input_out_point, _) = gen_cell(
        &mut data_loader,
        capacity_bytes!(1000),
        lock_args.clone(),
        Some(type_id_args.clone()),
    );
    let input_cell_meta = CellMetaBuilder::from_cell_output(input_cell, Bytes::new())
        .out_point(input_out_point.clone().cell.unwrap())
        .build();
    let resolved_inputs = vec![ResolvedOutPoint::cell_only(input_cell_meta)];
    let mut resolved_deps = vec![];

    let (output_cell, _, output_data) = gen_cell(
        &mut data_loader,
        capacity_bytes!(990),
        vec![],
        Some(type_id_args.clone()),
    );
    let builder = TransactionBuilder::default()
        .input(CellInput::new(input_out_point, 0))
        .output(output_cell)
        .output_data(output_data);
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
fn test_type_id_creation() {
    let mut data_loader = DummyDataLoader::new();
    let (privkey, lock_args) = gen_lock();

    let (input_cell, input_out_point, _) = gen_cell(
        &mut data_loader,
        capacity_bytes!(1000),
        lock_args.clone(),
        None,
    );
    let input_cell_meta = CellMetaBuilder::from_cell_output(input_cell, Bytes::new())
        .out_point(input_out_point.clone().cell.unwrap())
        .build();
    let cell_input = CellInput::new(input_out_point, 0);
    let resolved_inputs = vec![ResolvedOutPoint::cell_only(input_cell_meta)];
    let mut resolved_deps = vec![];

    let type_id_args = {
        let mut builder = FlatBufferBuilder::new();
        let offset = FbsCellInput::build(&mut builder, &cell_input);
        builder.finish(offset, None);
        let data = builder.finished_data();

        let hash = blake2b_256(&data);
        vec![Bytes::from(&hash[..])]
    };

    let (output_cell, _, output_data) = gen_cell(
        &mut data_loader,
        capacity_bytes!(990),
        vec![],
        Some(type_id_args.clone()),
    );
    let builder = TransactionBuilder::default()
        .input(cell_input)
        .output(output_cell)
        .output_data(output_data);
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
fn test_type_id_termination() {
    let mut data_loader = DummyDataLoader::new();
    let (privkey, lock_args) = gen_lock();

    let type_id_args = {
        let mut rng = thread_rng();
        let mut buf = [0u8; 32];
        rng.fill(&mut buf);
        vec![Bytes::from(&buf[..])]
    };

    let (input_cell, input_out_point, _) = gen_cell(
        &mut data_loader,
        capacity_bytes!(1000),
        lock_args.clone(),
        Some(type_id_args.clone()),
    );
    let input_cell_meta = CellMetaBuilder::from_cell_output(input_cell, Bytes::new())
        .out_point(input_out_point.clone().cell.unwrap())
        .build();
    let resolved_inputs = vec![ResolvedOutPoint::cell_only(input_cell_meta)];
    let mut resolved_deps = vec![];

    let (output_cell, _, output_data) =
        gen_cell(&mut data_loader, capacity_bytes!(990), vec![], None);
    let builder = TransactionBuilder::default()
        .input(CellInput::new(input_out_point, 0))
        .output(output_cell)
        .output_data(output_data);
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
fn test_type_id_invalid_creation() {
    let mut data_loader = DummyDataLoader::new();
    let (privkey, lock_args) = gen_lock();

    let (input_cell, input_out_point, _) = gen_cell(
        &mut data_loader,
        capacity_bytes!(1000),
        lock_args.clone(),
        None,
    );
    let input_cell_meta = CellMetaBuilder::from_cell_output(input_cell, Bytes::new())
        .out_point(input_out_point.clone().cell.unwrap())
        .build();
    let cell_input = CellInput::new(input_out_point, 0);
    let resolved_inputs = vec![ResolvedOutPoint::cell_only(input_cell_meta)];
    let mut resolved_deps = vec![];

    let type_id_args = {
        let hash = blake2b_256(&"abc");
        vec![Bytes::from(&hash[..])]
    };

    let (output_cell, _, output_data) = gen_cell(
        &mut data_loader,
        capacity_bytes!(990),
        vec![],
        Some(type_id_args.clone()),
    );
    let builder = TransactionBuilder::default()
        .input(cell_input)
        .output(output_cell)
        .output_data(output_data);
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
    assert_eq!(verify_result, Err(ScriptError::ValidationFailure(-23)));
}

#[test]
fn test_type_id_one_in_two_out() {
    let mut data_loader = DummyDataLoader::new();
    let (privkey, lock_args) = gen_lock();

    let (input_cell, input_out_point, _) = gen_cell(
        &mut data_loader,
        capacity_bytes!(2000),
        lock_args.clone(),
        None,
    );
    let input_cell_meta = CellMetaBuilder::from_cell_output(input_cell, Bytes::new())
        .out_point(input_out_point.clone().cell.unwrap())
        .build();
    let cell_input = CellInput::new(input_out_point, 0);
    let resolved_inputs = vec![ResolvedOutPoint::cell_only(input_cell_meta)];
    let mut resolved_deps = vec![];

    let type_id_args = {
        let mut builder = FlatBufferBuilder::new();
        let offset = FbsCellInput::build(&mut builder, &cell_input);
        builder.finish(offset, None);
        let data = builder.finished_data();

        let hash = blake2b_256(&data);
        vec![Bytes::from(&hash[..])]
    };

    let (output_cell, _, output_data) = gen_cell(
        &mut data_loader,
        capacity_bytes!(990),
        vec![],
        Some(type_id_args.clone()),
    );
    let (output_cell2, _, output_data2) = gen_cell(
        &mut data_loader,
        capacity_bytes!(990),
        vec![],
        Some(type_id_args.clone()),
    );
    let builder = TransactionBuilder::default()
        .input(cell_input)
        .output(output_cell)
        .output_data(output_data)
        .output(output_cell2)
        .output_data(output_data2);
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
    assert_eq!(verify_result, Err(ScriptError::ValidationFailure(-19)));
}
