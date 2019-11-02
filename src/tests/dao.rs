use super::{sign_tx, DummyDataLoader, DAO_BIN, MAX_CYCLES, SECP256K1_DATA_BIN, SIGHASH_ALL_BIN};
use byteorder::{ByteOrder, LittleEndian};
use ckb_crypto::secp::{Generator, Privkey};
use ckb_dao_utils::pack_dao_data;
use ckb_error::assert_error_eq;
use ckb_script::{ScriptError, TransactionScriptsVerifier};
use ckb_types::{
    bytes::Bytes,
    core::{
        cell::{CellMeta, CellMetaBuilder, ResolvedTransaction},
        BlockNumber, Capacity, DepType, EpochExt, EpochNumber, EpochNumberWithFraction,
        HeaderBuilder, HeaderView, ScriptHashType, TransactionBuilder, TransactionInfo,
        TransactionView,
    },
    packed::{Byte32, CellDep, CellInput, CellOutput, OutPoint, Script, WitnessArgs},
    prelude::*,
};
use rand::{thread_rng, Rng};

const ERROR_SYSCALL: i8 = -4;
const ERROR_INVALID_WITHDRAW_BLOCK: i8 = -14;
const ERROR_INCORRECT_CAPACITY: i8 = -15;
const ERROR_INCORRECT_SINCE: i8 = -17;
const ERROR_TOO_MANY_OUTPUT_CELLS: i8 = -18;
const ERROR_NEWLY_CREATED_CELL: i8 = -19;
const ERROR_INVALID_WITHDRAWING_CELL: i8 = -20;

fn cell_output_with_only_capacity(shannons: u64) -> CellOutput {
    CellOutput::new_builder()
        .capacity(Capacity::shannons(shannons).pack())
        .build()
}

fn generate_random_out_point() -> OutPoint {
    let tx_hash = {
        let mut rng = thread_rng();
        let mut buf = [0u8; 32];
        rng.fill(&mut buf);
        buf.pack()
    };
    OutPoint::new(tx_hash, 0)
}

fn script_cell(script_data: &Bytes) -> (CellOutput, OutPoint) {
    let out_point = generate_random_out_point();

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
    CellOutput::calc_data_hash(&SIGHASH_ALL_BIN)
}

fn dao_code_hash() -> Byte32 {
    CellOutput::calc_data_hash(&DAO_BIN)
}

fn gen_normal_cell(
    dummy: &mut DummyDataLoader,
    capacity: Capacity,
    lock_args: Bytes,
) -> (CellOutput, OutPoint) {
    let out_point = generate_random_out_point();

    let lock = Script::new_builder()
        .args(lock_args.pack())
        .code_hash(secp_code_hash())
        .hash_type(ScriptHashType::Data.into())
        .build();
    let cell = CellOutput::new_builder()
        .capacity(capacity.pack())
        .lock(lock)
        .build();
    dummy
        .cells
        .insert(out_point.clone(), (cell.clone(), Bytes::new()));

    (cell, out_point)
}

fn gen_dao_cell(
    dummy: &mut DummyDataLoader,
    capacity: Capacity,
    lock_args: Bytes,
) -> (CellOutput, OutPoint) {
    let out_point = generate_random_out_point();

    let lock = Script::new_builder()
        .args(lock_args.pack())
        .code_hash(secp_code_hash())
        .hash_type(ScriptHashType::Data.into())
        .build();
    let type_ = Script::new_builder()
        .args(Bytes::new().pack())
        .code_hash(dao_code_hash())
        .hash_type(ScriptHashType::Data.into())
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

fn gen_header(
    number: BlockNumber,
    ar: u64,
    epoch_number: EpochNumber,
    epoch_start_block_number: BlockNumber,
    epoch_length: BlockNumber,
) -> (HeaderView, EpochExt) {
    let epoch_ext = EpochExt::new_builder()
        .number(epoch_number)
        .start_number(epoch_start_block_number)
        .length(epoch_length)
        .build();
    let header = HeaderBuilder::default()
        .number(number.pack())
        .epoch(epoch_ext.number_with_fraction(number).pack())
        .dao(pack_dao_data(
            ar,
            Capacity::shannons(0),
            Capacity::shannons(0),
            Capacity::shannons(0),
        ))
        .build();
    (header, epoch_ext)
}

fn gen_lock() -> (Privkey, Bytes) {
    let privkey = Generator::random_privkey();
    let pubkey = privkey.pubkey().expect("pubkey");
    // compute pubkey hash
    let pubkey_hash = {
        let ser_pk = pubkey.serialize();
        ckb_hash::blake2b_256(ser_pk)[..20].to_vec()
    };
    let lock_args = pubkey_hash.into();
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
        .cell_dep(
            CellDep::new_builder()
                .out_point(secp_out_point)
                .dep_type(DepType::Code.into())
                .build(),
        )
        .cell_dep(
            CellDep::new_builder()
                .out_point(secp_data_out_point)
                .dep_type(DepType::Code.into())
                .build(),
        )
        .cell_dep(
            CellDep::new_builder()
                .out_point(dao_out_point)
                .dep_type(DepType::Code.into())
                .build(),
        )
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

    let (deposit_header, deposit_epoch) = gen_header(1554, 10000000, 35, 1000, 1000);
    let (withdraw_header, withdraw_epoch) = gen_header(2000610, 10001000, 575, 2000000, 1100);
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
    data_loader
        .epoches
        .insert(deposit_header.hash(), deposit_epoch.clone());
    data_loader
        .epoches
        .insert(withdraw_header.hash(), withdraw_epoch.clone());

    let mut b = [0; 8];
    LittleEndian::write_u64(&mut b, 1554);
    let input_cell_meta = CellMetaBuilder::from_cell_output(cell, Bytes::from(&b[..]))
        .out_point(previous_out_point.clone())
        .transaction_info(TransactionInfo {
            block_hash: withdraw_header.hash(),
            block_number: withdraw_header.number(),
            block_epoch: EpochNumberWithFraction::new(575, 610, 1100),
            index: 0,
        })
        .build();

    let resolved_inputs = vec![input_cell_meta];
    let mut resolved_cell_deps = vec![];

    let mut b = [0; 8];
    LittleEndian::write_u64(&mut b, 1);
    let witness = WitnessArgs::new_builder()
        .type_(Bytes::from(&b[..]).pack())
        .build();
    let builder = TransactionBuilder::default()
        .input(CellInput::new(previous_out_point, 0x2003e8022a0002f3))
        .output(cell_output_with_only_capacity(123468105678))
        .output_data(Bytes::new().pack())
        .header_dep(withdraw_header.hash())
        .header_dep(deposit_header.hash())
        .witness(witness.as_bytes().pack());
    let (tx, mut resolved_cell_deps2) = complete_tx(&mut data_loader, builder);
    let tx = sign_tx(tx, &privkey);
    for dep in resolved_cell_deps2.drain(..) {
        resolved_cell_deps.push(dep);
    }
    let rtx = ResolvedTransaction {
        transaction: tx,
        resolved_inputs,
        resolved_cell_deps,
        resolved_dep_groups: vec![],
    };

    let verify_result = TransactionScriptsVerifier::new(&rtx, &data_loader).verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_dao_single_cell_epoch_edge() {
    let mut data_loader = DummyDataLoader::new();
    let (privkey, lock_args) = gen_lock();

    let (deposit_header, deposit_epoch) = gen_header(1554, 10000000, 35, 1000, 1000);
    let (withdraw_header, withdraw_epoch) = gen_header(2000555, 10001000, 575, 2000000, 1000);
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
    data_loader
        .epoches
        .insert(deposit_header.hash(), deposit_epoch.clone());
    data_loader
        .epoches
        .insert(withdraw_header.hash(), withdraw_epoch.clone());

    let mut b = [0; 8];
    LittleEndian::write_u64(&mut b, 1554);
    let input_cell_meta = CellMetaBuilder::from_cell_output(cell, Bytes::from(&b[..]))
        .out_point(previous_out_point.clone())
        .transaction_info(TransactionInfo {
            block_hash: withdraw_header.hash(),
            block_number: withdraw_header.number(),
            block_epoch: EpochNumberWithFraction::new(575, 555, 1000),
            index: 0,
        })
        .build();

    let resolved_inputs = vec![input_cell_meta];
    let mut resolved_cell_deps = vec![];

    let mut b = [0; 8];
    LittleEndian::write_u64(&mut b, 1);
    let witness = WitnessArgs::new_builder()
        .type_(Bytes::from(&b[..]).pack())
        .build();
    let builder = TransactionBuilder::default()
        .input(CellInput::new(previous_out_point, 0x2003e8022a0002f3))
        .output(cell_output_with_only_capacity(123468105678))
        .output_data(Bytes::new().pack())
        .header_dep(withdraw_header.hash())
        .header_dep(deposit_header.hash())
        .witness(witness.as_bytes().pack());
    let (tx, mut resolved_cell_deps2) = complete_tx(&mut data_loader, builder);
    let tx = sign_tx(tx, &privkey);
    for dep in resolved_cell_deps2.drain(..) {
        resolved_cell_deps.push(dep);
    }
    let rtx = ResolvedTransaction {
        transaction: tx,
        resolved_inputs,
        resolved_cell_deps,
        resolved_dep_groups: vec![],
    };

    let verify_result = TransactionScriptsVerifier::new(&rtx, &data_loader).verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_dao_single_cell_start_of_epoch() {
    let mut data_loader = DummyDataLoader::new();
    let (privkey, lock_args) = gen_lock();

    let (deposit_header, deposit_epoch) = gen_header(1000, 10000000, 35, 1000, 1000);
    let (withdraw_header, withdraw_epoch) = gen_header(2000001, 10001000, 575, 2000000, 1100);
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
    data_loader
        .epoches
        .insert(deposit_header.hash(), deposit_epoch.clone());
    data_loader
        .epoches
        .insert(withdraw_header.hash(), withdraw_epoch.clone());

    let mut b = [0; 8];
    LittleEndian::write_u64(&mut b, 1000);
    let input_cell_meta = CellMetaBuilder::from_cell_output(cell, Bytes::from(&b[..]))
        .out_point(previous_out_point.clone())
        .transaction_info(TransactionInfo {
            block_hash: withdraw_header.hash(),
            block_number: withdraw_header.number(),
            block_epoch: EpochNumberWithFraction::new(575, 1, 1100),
            index: 0,
        })
        .build();

    let resolved_inputs = vec![input_cell_meta];
    let mut resolved_cell_deps = vec![];

    let mut b = [0; 8];
    LittleEndian::write_u64(&mut b, 1);
    let witness = WitnessArgs::new_builder()
        .type_(Bytes::from(&b[..]).pack())
        .build();
    let builder = TransactionBuilder::default()
        .input(CellInput::new(previous_out_point, 0x2003e800000002f3))
        .output(cell_output_with_only_capacity(123468105678))
        .output_data(Bytes::new().pack())
        .header_dep(withdraw_header.hash())
        .header_dep(deposit_header.hash())
        .witness(witness.as_bytes().pack());
    let (tx, mut resolved_cell_deps2) = complete_tx(&mut data_loader, builder);
    let tx = sign_tx(tx, &privkey);
    for dep in resolved_cell_deps2.drain(..) {
        resolved_cell_deps.push(dep);
    }
    let rtx = ResolvedTransaction {
        transaction: tx,
        resolved_inputs,
        resolved_cell_deps,
        resolved_dep_groups: vec![],
    };

    let verify_result = TransactionScriptsVerifier::new(&rtx, &data_loader).verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_dao_single_cell_end_of_epoch() {
    let mut data_loader = DummyDataLoader::new();
    let (privkey, lock_args) = gen_lock();

    let (deposit_header, deposit_epoch) = gen_header(1999, 10000000, 35, 1000, 1000);
    let (withdraw_header, withdraw_epoch) = gen_header(2000000, 10001000, 576, 2000000, 1100);
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
    data_loader
        .epoches
        .insert(deposit_header.hash(), deposit_epoch.clone());
    data_loader
        .epoches
        .insert(withdraw_header.hash(), withdraw_epoch.clone());

    let mut b = [0; 8];
    LittleEndian::write_u64(&mut b, 1999);
    let input_cell_meta = CellMetaBuilder::from_cell_output(cell, Bytes::from(&b[..]))
        .out_point(previous_out_point.clone())
        .transaction_info(TransactionInfo {
            block_hash: withdraw_header.hash(),
            block_number: withdraw_header.number(),
            block_epoch: EpochNumberWithFraction::new(576, 0, 1100),
            index: 0,
        })
        .build();

    let resolved_inputs = vec![input_cell_meta];
    let mut resolved_cell_deps = vec![];

    let mut b = [0; 8];
    LittleEndian::write_u64(&mut b, 1);
    let witness = WitnessArgs::new_builder()
        .type_(Bytes::from(&b[..]).pack())
        .build();
    let builder = TransactionBuilder::default()
        .input(CellInput::new(previous_out_point, 0x2003e803e70002f3))
        .output(cell_output_with_only_capacity(123468105678))
        .output_data(Bytes::new().pack())
        .header_dep(withdraw_header.hash())
        .header_dep(deposit_header.hash())
        .witness(witness.as_bytes().pack());
    let (tx, mut resolved_cell_deps2) = complete_tx(&mut data_loader, builder);
    let tx = sign_tx(tx, &privkey);
    for dep in resolved_cell_deps2.drain(..) {
        resolved_cell_deps.push(dep);
    }
    let rtx = ResolvedTransaction {
        transaction: tx,
        resolved_inputs,
        resolved_cell_deps,
        resolved_dep_groups: vec![],
    };

    let verify_result = TransactionScriptsVerifier::new(&rtx, &data_loader).verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_dao_single_cell_with_fees() {
    let mut data_loader = DummyDataLoader::new();
    let (privkey, lock_args) = gen_lock();

    let (deposit_header, deposit_epoch) = gen_header(1554, 10000000, 35, 1000, 1000);
    let (withdraw_header, withdraw_epoch) = gen_header(2000610, 10001000, 575, 2000000, 1100);
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
    data_loader
        .epoches
        .insert(deposit_header.hash(), deposit_epoch.clone());
    data_loader
        .epoches
        .insert(withdraw_header.hash(), withdraw_epoch.clone());

    let mut b = [0; 8];
    LittleEndian::write_u64(&mut b, 1554);
    let input_cell_meta = CellMetaBuilder::from_cell_output(cell, Bytes::from(&b[..]))
        .out_point(previous_out_point.clone())
        .transaction_info(TransactionInfo {
            block_hash: withdraw_header.hash(),
            block_number: withdraw_header.number(),
            block_epoch: EpochNumberWithFraction::new(575, 610, 1100),
            index: 0,
        })
        .build();

    let resolved_inputs = vec![input_cell_meta];
    let mut resolved_cell_deps = vec![];

    let mut b = [0; 8];
    LittleEndian::write_u64(&mut b, 1);
    let witness = WitnessArgs::new_builder()
        .type_(Bytes::from(&b[..]).pack())
        .build();
    let builder = TransactionBuilder::default()
        .input(CellInput::new(previous_out_point, 0x2003e800000002f4))
        .output(cell_output_with_only_capacity(123458045678))
        .output_data(Bytes::new().pack())
        .header_dep(withdraw_header.hash())
        .header_dep(deposit_header.hash())
        .witness(witness.as_bytes().pack());
    let (tx, mut resolved_cell_deps2) = complete_tx(&mut data_loader, builder);
    let tx = sign_tx(tx, &privkey);
    for dep in resolved_cell_deps2.drain(..) {
        resolved_cell_deps.push(dep);
    }
    let rtx = ResolvedTransaction {
        transaction: tx,
        resolved_inputs,
        resolved_cell_deps,
        resolved_dep_groups: vec![],
    };

    let verify_result = TransactionScriptsVerifier::new(&rtx, &data_loader).verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_dao_single_cell_with_dao_output_cell() {
    let mut data_loader = DummyDataLoader::new();
    let (privkey, lock_args) = gen_lock();

    let (deposit_header, deposit_epoch) = gen_header(1554, 10000000, 35, 1000, 1000);
    let (withdraw_header, withdraw_epoch) = gen_header(2000610, 10001000, 575, 2000000, 1100);
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
    data_loader
        .epoches
        .insert(deposit_header.hash(), deposit_epoch.clone());
    data_loader
        .epoches
        .insert(withdraw_header.hash(), withdraw_epoch.clone());

    let mut b = [0; 8];
    LittleEndian::write_u64(&mut b, 1554);
    let input_cell_meta = CellMetaBuilder::from_cell_output(cell, Bytes::from(&b[..]))
        .out_point(previous_out_point.clone())
        .transaction_info(TransactionInfo {
            block_hash: withdraw_header.hash(),
            block_number: withdraw_header.number(),
            block_epoch: EpochNumberWithFraction::new(575, 610, 1100),
            index: 0,
        })
        .build();

    let resolved_inputs = vec![input_cell_meta];
    let mut resolved_cell_deps = vec![];

    let mut b = [0; 8];
    LittleEndian::write_u64(&mut b, 1);
    let witness = WitnessArgs::new_builder()
        .type_(Bytes::from(&b[..]).pack())
        .build();
    let type_ = Script::new_builder()
        .code_hash(dao_code_hash())
        .hash_type(ScriptHashType::Data.into())
        .build();
    let builder = TransactionBuilder::default()
        .input(CellInput::new(previous_out_point, 0x2003e8022a0002f3))
        .output(
            cell_output_with_only_capacity(123468045678)
                .as_builder()
                .type_(Some(type_).pack())
                .build(),
        )
        .output_data(Bytes::from(&[0u8; 8][..]).pack())
        .header_dep(withdraw_header.hash())
        .header_dep(deposit_header.hash())
        .witness(witness.as_bytes().pack());
    let (tx, mut resolved_cell_deps2) = complete_tx(&mut data_loader, builder);
    let tx = sign_tx(tx, &privkey);
    for dep in resolved_cell_deps2.drain(..) {
        resolved_cell_deps.push(dep);
    }
    let rtx = ResolvedTransaction {
        transaction: tx,
        resolved_inputs,
        resolved_cell_deps,
        resolved_dep_groups: vec![],
    };

    let verify_result = TransactionScriptsVerifier::new(&rtx, &data_loader).verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_dao_multiple_cells() {
    let mut data_loader = DummyDataLoader::new();
    let (privkey, lock_args) = gen_lock();

    let (deposit_header, deposit_epoch) = gen_header(1554, 10000000, 35, 1000, 1000);
    let (deposit_header2, deposit_epoch2) = gen_header(1564, 10000000, 35, 1000, 1000);
    let (withdraw_header, withdraw_epoch) = gen_header(2000610, 10001000, 575, 2000000, 1100);
    let (withdraw_header2, withdraw_epoch2) = gen_header(2000621, 10001000, 575, 2000000, 1100);
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
    data_loader
        .epoches
        .insert(deposit_header.hash(), deposit_epoch.clone());
    data_loader
        .epoches
        .insert(deposit_header2.hash(), deposit_epoch2.clone());
    data_loader
        .epoches
        .insert(withdraw_header.hash(), withdraw_epoch.clone());
    data_loader
        .epoches
        .insert(withdraw_header2.hash(), withdraw_epoch2.clone());

    let mut b = [0; 8];
    LittleEndian::write_u64(&mut b, 1554);
    let input_cell_meta = CellMetaBuilder::from_cell_output(cell, Bytes::from(&b[..]))
        .out_point(previous_out_point.clone())
        .transaction_info(TransactionInfo {
            block_hash: withdraw_header.hash(),
            block_number: withdraw_header.number(),
            block_epoch: EpochNumberWithFraction::new(575, 610, 1100),
            index: 0,
        })
        .build();
    let mut b = [0; 8];
    LittleEndian::write_u64(&mut b, 1564);
    let input_cell_meta2 = CellMetaBuilder::from_cell_output(cell2, Bytes::from(&b[..]))
        .out_point(previous_out_point2.clone())
        .transaction_info(TransactionInfo {
            block_hash: withdraw_header2.hash(),
            block_number: withdraw_header2.number(),
            block_epoch: EpochNumberWithFraction::new(575, 621, 1100),
            index: 0,
        })
        .build();

    let resolved_inputs = vec![input_cell_meta, input_cell_meta2];
    let mut resolved_cell_deps = vec![];

    let mut b = [0; 8];
    LittleEndian::write_u64(&mut b, 2);
    let witness = WitnessArgs::new_builder()
        .type_(Bytes::from(&b[..]).pack())
        .build();
    let mut b2 = [0; 8];
    LittleEndian::write_u64(&mut b2, 3);
    let witness2 = WitnessArgs::new_builder()
        .type_(Bytes::from(&b2[..]).pack())
        .build();
    let builder = TransactionBuilder::default()
        .input(CellInput::new(previous_out_point, 0x2003e800000002f4))
        .input(CellInput::new(previous_out_point2, 0x2003e802340002f3))
        .output(cell_output_with_only_capacity(123468106670))
        .output(cell_output_with_only_capacity(123468105686))
        .outputs_data(vec![Bytes::new(); 2].pack())
        .header_dep(withdraw_header.hash())
        .header_dep(withdraw_header2.hash())
        .header_dep(deposit_header.hash())
        .header_dep(deposit_header2.hash())
        .witness(witness.as_bytes().pack())
        .witness(witness2.as_bytes().pack());
    let (tx, mut resolved_cell_deps2) = complete_tx(&mut data_loader, builder);
    let tx = sign_tx(tx, &privkey);
    for dep in resolved_cell_deps2.drain(..) {
        resolved_cell_deps.push(dep);
    }
    let rtx = ResolvedTransaction {
        transaction: tx,
        resolved_inputs,
        resolved_cell_deps,
        resolved_dep_groups: vec![],
    };

    let verify_result = TransactionScriptsVerifier::new(&rtx, &data_loader).verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_dao_missing_deposit_header() {
    let mut data_loader = DummyDataLoader::new();
    let (privkey, lock_args) = gen_lock();

    let (withdraw_header, withdraw_epoch) = gen_header(2000610, 10001000, 575, 2000000, 1100);
    let (cell, previous_out_point) = gen_dao_cell(
        &mut data_loader,
        Capacity::shannons(123456780000),
        lock_args,
    );
    data_loader
        .headers
        .insert(withdraw_header.hash(), withdraw_header.clone());
    data_loader
        .epoches
        .insert(withdraw_header.hash(), withdraw_epoch.clone());

    let cell_out_point = previous_out_point.clone();
    let previous_out_point = OutPoint::new_builder()
        .tx_hash(cell_out_point.tx_hash())
        .index(cell_out_point.index())
        .build();

    let mut b = [0; 8];
    LittleEndian::write_u64(&mut b, 1554);
    let input_cell_meta = CellMetaBuilder::from_cell_output(cell, Bytes::from(&b[..]))
        .out_point(previous_out_point.clone())
        .transaction_info(TransactionInfo {
            block_hash: withdraw_header.hash(),
            block_number: withdraw_header.number(),
            block_epoch: EpochNumberWithFraction::new(575, 610, 1100),
            index: 0,
        })
        .build();

    let resolved_inputs = vec![input_cell_meta];
    let mut resolved_cell_deps = vec![];

    let mut b = [0; 8];
    LittleEndian::write_u64(&mut b, 1);
    let witness = WitnessArgs::new_builder()
        .type_(Bytes::from(&b[..]).pack())
        .build();
    let builder = TransactionBuilder::default()
        .input(CellInput::new(previous_out_point, 0x2003e80000000320))
        .output(cell_output_with_only_capacity(123468045678))
        .output_data(Bytes::new().pack())
        .header_dep(withdraw_header.hash())
        .witness(witness.as_bytes().pack());
    let (tx, mut resolved_cell_deps2) = complete_tx(&mut data_loader, builder);
    let tx = sign_tx(tx, &privkey);
    for dep in resolved_cell_deps2.drain(..) {
        resolved_cell_deps.push(dep);
    }
    let rtx = ResolvedTransaction {
        transaction: tx,
        resolved_inputs,
        resolved_cell_deps,
        resolved_dep_groups: vec![],
    };

    let verify_result = TransactionScriptsVerifier::new(&rtx, &data_loader).verify(MAX_CYCLES);
    assert_error_eq!(
        verify_result.unwrap_err(),
        ScriptError::ValidationFailure(1),
    );
}

#[test]
fn test_dao_missing_withdraw_header() {
    let mut data_loader = DummyDataLoader::new();
    let (privkey, lock_args) = gen_lock();

    let (deposit_header, deposit_epoch) = gen_header(1554, 10000000, 35, 1000, 1000);
    let (withdraw_header, _withdraw_epoch) = gen_header(2000610, 10001000, 575, 2000000, 1100);
    let (cell, previous_out_point) = gen_dao_cell(
        &mut data_loader,
        Capacity::shannons(123456780000),
        lock_args,
    );

    data_loader
        .headers
        .insert(deposit_header.hash(), deposit_header.clone());
    data_loader
        .epoches
        .insert(deposit_header.hash(), deposit_epoch.clone());

    let mut b = [0; 8];
    LittleEndian::write_u64(&mut b, 1554);
    let input_cell_meta = CellMetaBuilder::from_cell_output(cell, Bytes::from(&b[..]))
        .out_point(previous_out_point.clone())
        .transaction_info(TransactionInfo {
            block_hash: withdraw_header.hash(),
            block_number: withdraw_header.number(),
            block_epoch: EpochNumberWithFraction::new(575, 610, 1100),
            index: 0,
        })
        .build();

    let resolved_inputs = vec![input_cell_meta];
    let mut resolved_cell_deps = vec![];

    let mut b = [0; 8];
    LittleEndian::write_u64(&mut b, 0);
    let witness = WitnessArgs::new_builder()
        .type_(Bytes::from(&b[..]).pack())
        .build();
    let builder = TransactionBuilder::default()
        .input(CellInput::new(previous_out_point, 0x2003e80000000320))
        .output(cell_output_with_only_capacity(123468045678))
        .output_data(Bytes::new().pack())
        .header_dep(deposit_header.hash())
        .witness(witness.as_bytes().pack());
    let (tx, mut resolved_cell_deps2) = complete_tx(&mut data_loader, builder);
    let tx = sign_tx(tx, &privkey);
    for dep in resolved_cell_deps2.drain(..) {
        resolved_cell_deps.push(dep);
    }
    let rtx = ResolvedTransaction {
        transaction: tx,
        resolved_inputs,
        resolved_cell_deps,
        resolved_dep_groups: vec![],
    };

    let verify_result = TransactionScriptsVerifier::new(&rtx, &data_loader).verify(MAX_CYCLES);
    assert_error_eq!(
        verify_result.unwrap_err(),
        ScriptError::ValidationFailure(2),
    );
}

#[test]
fn test_dao_invalid_deposit_header() {
    let mut data_loader = DummyDataLoader::new();
    let (privkey, lock_args) = gen_lock();

    let (deposit_header, deposit_epoch) = gen_header(1554, 10000000, 35, 1000, 1000);
    let (withdraw_header, withdraw_epoch) = gen_header(2000600, 10001000, 575, 2000000, 1100);
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
    data_loader
        .epoches
        .insert(deposit_header.hash(), deposit_epoch.clone());
    data_loader
        .epoches
        .insert(withdraw_header.hash(), withdraw_epoch.clone());

    let mut b = [0; 8];
    LittleEndian::write_u64(&mut b, 1554);
    let input_cell_meta = CellMetaBuilder::from_cell_output(cell, Bytes::from(&b[..]))
        .out_point(previous_out_point.clone())
        .transaction_info(TransactionInfo {
            block_hash: withdraw_header.hash(),
            block_number: withdraw_header.number(),
            block_epoch: EpochNumberWithFraction::new(575, 610, 1100),
            index: 0,
        })
        .build();

    let resolved_inputs = vec![input_cell_meta];
    let mut resolved_cell_deps = vec![];

    let mut b = [0; 8];
    LittleEndian::write_u64(&mut b, 0);
    let witness = WitnessArgs::new_builder()
        .type_(Bytes::from(&b[..]).pack())
        .build();
    let builder = TransactionBuilder::default()
        .input(CellInput::new(previous_out_point, 0x2003e80000000320))
        .output(cell_output_with_only_capacity(123468045678))
        .output_data(Bytes::new().pack())
        .header_dep(withdraw_header.hash())
        .witness(witness.as_bytes().pack());
    let (tx, mut resolved_cell_deps2) = complete_tx(&mut data_loader, builder);
    let tx = sign_tx(tx, &privkey);
    for dep in resolved_cell_deps2.drain(..) {
        resolved_cell_deps.push(dep);
    }
    let rtx = ResolvedTransaction {
        transaction: tx,
        resolved_inputs,
        resolved_cell_deps,
        resolved_dep_groups: vec![],
    };

    let verify_result = TransactionScriptsVerifier::new(&rtx, &data_loader).verify(MAX_CYCLES);
    assert_error_eq!(
        verify_result.unwrap_err(),
        ScriptError::ValidationFailure(ERROR_INVALID_WITHDRAW_BLOCK),
    );
}

#[test]
fn test_dao_invalid_withdraw_amount() {
    let mut data_loader = DummyDataLoader::new();
    let (privkey, lock_args) = gen_lock();

    let (deposit_header, deposit_epoch) = gen_header(1554, 10000000, 35, 1000, 1000);
    let (withdraw_header, withdraw_epoch) = gen_header(2000610, 10001000, 575, 2000000, 1100);
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
    data_loader
        .epoches
        .insert(deposit_header.hash(), deposit_epoch.clone());
    data_loader
        .epoches
        .insert(withdraw_header.hash(), withdraw_epoch.clone());

    let mut b = [0; 8];
    LittleEndian::write_u64(&mut b, 1554);
    let input_cell_meta = CellMetaBuilder::from_cell_output(cell, Bytes::from(&b[..]))
        .out_point(previous_out_point.clone())
        .transaction_info(TransactionInfo {
            block_hash: withdraw_header.hash(),
            block_number: withdraw_header.number(),
            block_epoch: EpochNumberWithFraction::new(575, 610, 1100),
            index: 0,
        })
        .build();

    let resolved_inputs = vec![input_cell_meta];
    let mut resolved_cell_deps = vec![];

    let mut b = [0; 8];
    LittleEndian::write_u64(&mut b, 1);
    let witness = WitnessArgs::new_builder()
        .type_(Bytes::from(&b[..]).pack())
        .build();
    let builder = TransactionBuilder::default()
        .input(CellInput::new(previous_out_point, 0x2003e8022a0002f3))
        .output(cell_output_with_only_capacity(123488045678))
        .output_data(Bytes::new().pack())
        .header_dep(withdraw_header.hash())
        .header_dep(deposit_header.hash())
        .witness(witness.as_bytes().pack());
    let (tx, mut resolved_cell_deps2) = complete_tx(&mut data_loader, builder);
    let tx = sign_tx(tx, &privkey);
    for dep in resolved_cell_deps2.drain(..) {
        resolved_cell_deps.push(dep);
    }
    let rtx = ResolvedTransaction {
        transaction: tx,
        resolved_inputs,
        resolved_cell_deps,
        resolved_dep_groups: vec![],
    };

    let verify_result = TransactionScriptsVerifier::new(&rtx, &data_loader).verify(MAX_CYCLES);
    assert_error_eq!(
        verify_result.unwrap_err(),
        ScriptError::ValidationFailure(ERROR_INCORRECT_CAPACITY),
    );
}

#[test]
fn test_dao_invalid_since() {
    let mut data_loader = DummyDataLoader::new();
    let (privkey, lock_args) = gen_lock();

    let (deposit_header, deposit_epoch) = gen_header(1554, 10000000, 35, 1000, 1000);
    let (withdraw_header, withdraw_epoch) = gen_header(2000610, 10001000, 575, 2000000, 1100);
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
    data_loader
        .epoches
        .insert(deposit_header.hash(), deposit_epoch.clone());
    data_loader
        .epoches
        .insert(withdraw_header.hash(), withdraw_epoch.clone());

    let mut b = [0; 8];
    LittleEndian::write_u64(&mut b, 1554);
    let input_cell_meta = CellMetaBuilder::from_cell_output(cell, Bytes::from(&b[..]))
        .out_point(previous_out_point.clone())
        .transaction_info(TransactionInfo {
            block_hash: withdraw_header.hash(),
            block_number: withdraw_header.number(),
            block_epoch: EpochNumberWithFraction::new(575, 610, 1100),
            index: 0,
        })
        .build();

    let resolved_inputs = vec![input_cell_meta];
    let mut resolved_cell_deps = vec![];

    let mut b = [0; 8];
    LittleEndian::write_u64(&mut b, 1);
    let witness = WitnessArgs::new_builder()
        .type_(Bytes::from(&b[..]).pack())
        .build();
    let builder = TransactionBuilder::default()
        .input(CellInput::new(previous_out_point, 0x2003e802290002f3))
        .output(cell_output_with_only_capacity(123468045678))
        .output_data(Bytes::new().pack())
        .header_dep(withdraw_header.hash())
        .header_dep(deposit_header.hash())
        .witness(witness.as_bytes().pack());
    let (tx, mut resolved_cell_deps2) = complete_tx(&mut data_loader, builder);
    let tx = sign_tx(tx, &privkey);
    for dep in resolved_cell_deps2.drain(..) {
        resolved_cell_deps.push(dep);
    }

    let rtx = ResolvedTransaction {
        transaction: tx,
        resolved_inputs,
        resolved_cell_deps,
        resolved_dep_groups: vec![],
    };

    let verify_result = TransactionScriptsVerifier::new(&rtx, &data_loader).verify(MAX_CYCLES);
    assert_error_eq!(
        verify_result.unwrap_err(),
        ScriptError::ValidationFailure(ERROR_INCORRECT_SINCE),
    );
}

#[test]
fn test_dao_invalid_withdraw_from_deposited_cell() {
    let mut data_loader = DummyDataLoader::new();
    let (privkey, lock_args) = gen_lock();

    let (deposit_header, deposit_epoch) = gen_header(1554, 10000000, 35, 1000, 1000);
    let (withdraw_header, withdraw_epoch) = gen_header(2000610, 10001000, 575, 2000000, 1100);
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
    data_loader
        .epoches
        .insert(deposit_header.hash(), deposit_epoch.clone());
    data_loader
        .epoches
        .insert(withdraw_header.hash(), withdraw_epoch.clone());

    let input_cell_meta = CellMetaBuilder::from_cell_output(cell, Bytes::from(&[0; 8][..]))
        .out_point(previous_out_point.clone())
        .transaction_info(TransactionInfo {
            block_hash: withdraw_header.hash(),
            block_number: withdraw_header.number(),
            block_epoch: EpochNumberWithFraction::new(575, 610, 1100),
            index: 0,
        })
        .build();

    let resolved_inputs = vec![input_cell_meta];
    let mut resolved_cell_deps = vec![];

    let mut b = [0; 8];
    LittleEndian::write_u64(&mut b, 1);
    let witness = WitnessArgs::new_builder()
        .type_(Bytes::from(&b[..]).pack())
        .build();
    let builder = TransactionBuilder::default()
        .input(CellInput::new(previous_out_point, 0x2003e8022a0002f3))
        .output(cell_output_with_only_capacity(123468105678))
        .output_data(Bytes::new().pack())
        .header_dep(withdraw_header.hash())
        .header_dep(deposit_header.hash())
        .witness(witness.as_bytes().pack());
    let (tx, mut resolved_cell_deps2) = complete_tx(&mut data_loader, builder);
    let tx = sign_tx(tx, &privkey);
    for dep in resolved_cell_deps2.drain(..) {
        resolved_cell_deps.push(dep);
    }
    let rtx = ResolvedTransaction {
        transaction: tx,
        resolved_inputs,
        resolved_cell_deps,
        resolved_dep_groups: vec![],
    };

    let verify_result = TransactionScriptsVerifier::new(&rtx, &data_loader).verify(MAX_CYCLES);
    assert_error_eq!(
        verify_result.unwrap_err(),
        ScriptError::ValidationFailure(2),
    );
}

#[test]
fn test_dao_deposit_cell() {
    let mut data_loader = DummyDataLoader::new();
    let (privkey, lock_args) = gen_lock();

    let (input_cell, previous_out_point) = gen_normal_cell(
        &mut data_loader,
        Capacity::shannons(1234567890),
        lock_args.clone(),
    );
    let (withdraw_header, _) = gen_header(2000610, 10001000, 575, 2000000, 1100);
    let input_cell_meta = CellMetaBuilder::from_cell_output(input_cell, Bytes::new())
        .out_point(previous_out_point.clone())
        .transaction_info(TransactionInfo {
            block_hash: withdraw_header.hash(),
            block_number: withdraw_header.number(),
            block_epoch: EpochNumberWithFraction::new(575, 610, 1100),
            index: 0,
        })
        .build();

    let resolved_inputs = vec![input_cell_meta];
    let mut resolved_cell_deps = vec![];

    let (output_cell, _) =
        gen_dao_cell(&mut data_loader, Capacity::shannons(1234567890), lock_args);

    let witness = WitnessArgs::new_builder().build();
    let builder = TransactionBuilder::default()
        .input(CellInput::new(previous_out_point, 0))
        .output(output_cell)
        .output_data(Bytes::from(&[0; 8][..]).pack())
        .witness(witness.as_bytes().pack());
    let (tx, mut resolved_cell_deps2) = complete_tx(&mut data_loader, builder);
    let tx = sign_tx(tx, &privkey);
    for dep in resolved_cell_deps2.drain(..) {
        resolved_cell_deps.push(dep);
    }
    let rtx = ResolvedTransaction {
        transaction: tx,
        resolved_inputs,
        resolved_cell_deps,
        resolved_dep_groups: vec![],
    };

    let verify_result = TransactionScriptsVerifier::new(&rtx, &data_loader).verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_dao_deposit_invalid_cell() {
    let mut data_loader = DummyDataLoader::new();
    let (privkey, lock_args) = gen_lock();

    let (input_cell, previous_out_point) = gen_normal_cell(
        &mut data_loader,
        Capacity::shannons(1234567890),
        lock_args.clone(),
    );
    let (withdraw_header, _) = gen_header(2000610, 10001000, 575, 2000000, 1100);
    let input_cell_meta = CellMetaBuilder::from_cell_output(input_cell, Bytes::new())
        .out_point(previous_out_point.clone())
        .transaction_info(TransactionInfo {
            block_hash: withdraw_header.hash(),
            block_number: withdraw_header.number(),
            block_epoch: EpochNumberWithFraction::new(575, 610, 1100),
            index: 0,
        })
        .build();

    let resolved_inputs = vec![input_cell_meta];
    let mut resolved_cell_deps = vec![];

    let (output_cell, _) =
        gen_dao_cell(&mut data_loader, Capacity::shannons(1234567890), lock_args);

    let witness = WitnessArgs::new_builder().build();
    let builder = TransactionBuilder::default()
        .input(CellInput::new(previous_out_point, 0))
        .output(output_cell)
        .output_data(Bytes::from(&[1; 8][..]).pack())
        .witness(witness.as_bytes().pack());
    let (tx, mut resolved_cell_deps2) = complete_tx(&mut data_loader, builder);
    let tx = sign_tx(tx, &privkey);
    for dep in resolved_cell_deps2.drain(..) {
        resolved_cell_deps.push(dep);
    }
    let rtx = ResolvedTransaction {
        transaction: tx,
        resolved_inputs,
        resolved_cell_deps,
        resolved_dep_groups: vec![],
    };

    let verify_result = TransactionScriptsVerifier::new(&rtx, &data_loader).verify(MAX_CYCLES);
    assert_error_eq!(
        verify_result.unwrap_err(),
        ScriptError::ValidationFailure(ERROR_NEWLY_CREATED_CELL),
    );
}

#[test]
fn test_dao_deposit_cell_missing_data() {
    let mut data_loader = DummyDataLoader::new();
    let (privkey, lock_args) = gen_lock();

    let (input_cell, previous_out_point) = gen_normal_cell(
        &mut data_loader,
        Capacity::shannons(1234567890),
        lock_args.clone(),
    );
    let (withdraw_header, _) = gen_header(2000610, 10001000, 575, 2000000, 1100);
    let input_cell_meta = CellMetaBuilder::from_cell_output(input_cell, Bytes::new())
        .out_point(previous_out_point.clone())
        .transaction_info(TransactionInfo {
            block_hash: withdraw_header.hash(),
            block_number: withdraw_header.number(),
            block_epoch: EpochNumberWithFraction::new(575, 610, 1100),
            index: 0,
        })
        .build();

    let resolved_inputs = vec![input_cell_meta];
    let mut resolved_cell_deps = vec![];

    let (output_cell, _) =
        gen_dao_cell(&mut data_loader, Capacity::shannons(1234567890), lock_args);

    let witness = WitnessArgs::new_builder().build();
    let builder = TransactionBuilder::default()
        .input(CellInput::new(previous_out_point, 0))
        .output(output_cell)
        .output_data(Bytes::new().pack())
        .witness(witness.as_bytes().pack());
    let (tx, mut resolved_cell_deps2) = complete_tx(&mut data_loader, builder);
    let tx = sign_tx(tx, &privkey);
    for dep in resolved_cell_deps2.drain(..) {
        resolved_cell_deps.push(dep);
    }
    let rtx = ResolvedTransaction {
        transaction: tx,
        resolved_inputs,
        resolved_cell_deps,
        resolved_dep_groups: vec![],
    };

    let verify_result = TransactionScriptsVerifier::new(&rtx, &data_loader).verify(MAX_CYCLES);
    assert_error_eq!(
        verify_result.unwrap_err(),
        ScriptError::ValidationFailure(ERROR_SYSCALL),
    );
}

#[test]
fn test_dao_create_withdrawing_cell() {
    let mut data_loader = DummyDataLoader::new();
    let (privkey, lock_args) = gen_lock();

    let (deposit_header, deposit_epoch) = gen_header(1554, 10000000, 35, 1000, 1000);
    let (cell, previous_out_point) = gen_dao_cell(
        &mut data_loader,
        Capacity::shannons(123456780000),
        lock_args.clone(),
    );

    data_loader
        .headers
        .insert(deposit_header.hash(), deposit_header.clone());
    data_loader
        .epoches
        .insert(deposit_header.hash(), deposit_epoch.clone());

    let input_cell_meta = CellMetaBuilder::from_cell_output(cell, Bytes::from(&[0; 8][..]))
        .out_point(previous_out_point.clone())
        .transaction_info(TransactionInfo {
            block_hash: deposit_header.hash(),
            block_number: deposit_header.number(),
            block_epoch: EpochNumberWithFraction::new(35, 554, 1000),
            index: 0,
        })
        .build();

    let resolved_inputs = vec![input_cell_meta];
    let mut resolved_cell_deps = vec![];

    let (output_cell, _) = gen_dao_cell(
        &mut data_loader,
        Capacity::shannons(123456780000),
        lock_args,
    );

    let mut b = [0; 8];
    LittleEndian::write_u64(&mut b, 1554);
    let witness = WitnessArgs::new_builder().build();
    let builder = TransactionBuilder::default()
        .input(CellInput::new(previous_out_point, 0))
        .output(output_cell)
        .output_data(Bytes::from(&b[..]).pack())
        .header_dep(deposit_header.hash())
        .witness(witness.as_bytes().pack());
    let (tx, mut resolved_cell_deps2) = complete_tx(&mut data_loader, builder);
    let tx = sign_tx(tx, &privkey);
    for dep in resolved_cell_deps2.drain(..) {
        resolved_cell_deps.push(dep);
    }
    let rtx = ResolvedTransaction {
        transaction: tx,
        resolved_inputs,
        resolved_cell_deps,
        resolved_dep_groups: vec![],
    };

    let verify_result = TransactionScriptsVerifier::new(&rtx, &data_loader).verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_dao_create_withdrawing_cell_with_different_lock() {
    let mut data_loader = DummyDataLoader::new();
    let (privkey, lock_args) = gen_lock();
    let (_, lock_args2) = gen_lock();

    let (deposit_header, deposit_epoch) = gen_header(1554, 10000000, 35, 1000, 1000);
    let (cell, previous_out_point) = gen_dao_cell(
        &mut data_loader,
        Capacity::shannons(123456780000),
        lock_args.clone(),
    );

    data_loader
        .headers
        .insert(deposit_header.hash(), deposit_header.clone());
    data_loader
        .epoches
        .insert(deposit_header.hash(), deposit_epoch.clone());

    let input_cell_meta = CellMetaBuilder::from_cell_output(cell, Bytes::from(&[0; 8][..]))
        .out_point(previous_out_point.clone())
        .transaction_info(TransactionInfo {
            block_hash: deposit_header.hash(),
            block_number: deposit_header.number(),
            block_epoch: EpochNumberWithFraction::new(35, 554, 1000),
            index: 0,
        })
        .build();

    let resolved_inputs = vec![input_cell_meta];
    let mut resolved_cell_deps = vec![];

    let (output_cell, _) = gen_dao_cell(
        &mut data_loader,
        Capacity::shannons(123456780000),
        lock_args2,
    );

    let mut b = [0; 8];
    LittleEndian::write_u64(&mut b, 1554);
    let witness = WitnessArgs::new_builder().build();
    let builder = TransactionBuilder::default()
        .input(CellInput::new(previous_out_point, 0))
        .output(output_cell)
        .output_data(Bytes::from(&b[..]).pack())
        .header_dep(deposit_header.hash())
        .witness(witness.as_bytes().pack());
    let (tx, mut resolved_cell_deps2) = complete_tx(&mut data_loader, builder);
    let tx = sign_tx(tx, &privkey);
    for dep in resolved_cell_deps2.drain(..) {
        resolved_cell_deps.push(dep);
    }
    let rtx = ResolvedTransaction {
        transaction: tx,
        resolved_inputs,
        resolved_cell_deps,
        resolved_dep_groups: vec![],
    };

    let verify_result = TransactionScriptsVerifier::new(&rtx, &data_loader).verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_dao_create_withdrawing_cell_with_invalid_type() {
    let mut data_loader = DummyDataLoader::new();
    let (privkey, lock_args) = gen_lock();

    let (deposit_header, deposit_epoch) = gen_header(1554, 10000000, 35, 1000, 1000);
    let (cell, previous_out_point) = gen_dao_cell(
        &mut data_loader,
        Capacity::shannons(123456780000),
        lock_args.clone(),
    );

    data_loader
        .headers
        .insert(deposit_header.hash(), deposit_header.clone());
    data_loader
        .epoches
        .insert(deposit_header.hash(), deposit_epoch.clone());

    let input_cell_meta = CellMetaBuilder::from_cell_output(cell, Bytes::from(&[0; 8][..]))
        .out_point(previous_out_point.clone())
        .transaction_info(TransactionInfo {
            block_hash: deposit_header.hash(),
            block_number: deposit_header.number(),
            block_epoch: EpochNumberWithFraction::new(35, 554, 1000),
            index: 0,
        })
        .build();

    let resolved_inputs = vec![input_cell_meta];
    let mut resolved_cell_deps = vec![];

    let (output_cell, _) = gen_normal_cell(
        &mut data_loader,
        Capacity::shannons(123456780000),
        lock_args,
    );

    let mut b = [0; 8];
    LittleEndian::write_u64(&mut b, 1554);
    let witness = WitnessArgs::new_builder().build();
    let builder = TransactionBuilder::default()
        .input(CellInput::new(previous_out_point, 0))
        .output(output_cell)
        .output_data(Bytes::from(&b[..]).pack())
        .header_dep(deposit_header.hash())
        .witness(witness.as_bytes().pack());
    let (tx, mut resolved_cell_deps2) = complete_tx(&mut data_loader, builder);
    let tx = sign_tx(tx, &privkey);
    for dep in resolved_cell_deps2.drain(..) {
        resolved_cell_deps.push(dep);
    }
    let rtx = ResolvedTransaction {
        transaction: tx,
        resolved_inputs,
        resolved_cell_deps,
        resolved_dep_groups: vec![],
    };

    let verify_result = TransactionScriptsVerifier::new(&rtx, &data_loader).verify(MAX_CYCLES);
    assert_error_eq!(
        verify_result.unwrap_err(),
        ScriptError::ValidationFailure(2),
    );
}

#[test]
fn test_dao_create_withdrawing_cell_with_invalid_data() {
    let mut data_loader = DummyDataLoader::new();
    let (privkey, lock_args) = gen_lock();

    let (deposit_header, deposit_epoch) = gen_header(1554, 10000000, 35, 1000, 1000);
    let (cell, previous_out_point) = gen_dao_cell(
        &mut data_loader,
        Capacity::shannons(123456780000),
        lock_args.clone(),
    );

    data_loader
        .headers
        .insert(deposit_header.hash(), deposit_header.clone());
    data_loader
        .epoches
        .insert(deposit_header.hash(), deposit_epoch.clone());

    let input_cell_meta = CellMetaBuilder::from_cell_output(cell, Bytes::from(&[0; 8][..]))
        .out_point(previous_out_point.clone())
        .transaction_info(TransactionInfo {
            block_hash: deposit_header.hash(),
            block_number: deposit_header.number(),
            block_epoch: EpochNumberWithFraction::new(35, 554, 1000),
            index: 0,
        })
        .build();

    let resolved_inputs = vec![input_cell_meta];
    let mut resolved_cell_deps = vec![];

    let (output_cell, _) = gen_dao_cell(
        &mut data_loader,
        Capacity::shannons(123456780000),
        lock_args,
    );

    let mut b = [0; 8];
    LittleEndian::write_u64(&mut b, 1590);
    let witness = WitnessArgs::new_builder().build();
    let builder = TransactionBuilder::default()
        .input(CellInput::new(previous_out_point, 0))
        .output(output_cell)
        .output_data(Bytes::from(&b[..]).pack())
        .header_dep(deposit_header.hash())
        .witness(witness.as_bytes().pack());
    let (tx, mut resolved_cell_deps2) = complete_tx(&mut data_loader, builder);
    let tx = sign_tx(tx, &privkey);
    for dep in resolved_cell_deps2.drain(..) {
        resolved_cell_deps.push(dep);
    }
    let rtx = ResolvedTransaction {
        transaction: tx,
        resolved_inputs,
        resolved_cell_deps,
        resolved_dep_groups: vec![],
    };

    let verify_result = TransactionScriptsVerifier::new(&rtx, &data_loader).verify(MAX_CYCLES);
    assert_error_eq!(
        verify_result.unwrap_err(),
        ScriptError::ValidationFailure(ERROR_INVALID_WITHDRAWING_CELL),
    );
}

#[test]
fn test_dao_create_withdrawing_cell_with_invalid_capacity() {
    let mut data_loader = DummyDataLoader::new();
    let (privkey, lock_args) = gen_lock();

    let (deposit_header, deposit_epoch) = gen_header(1554, 10000000, 35, 1000, 1000);
    let (cell, previous_out_point) = gen_dao_cell(
        &mut data_loader,
        Capacity::shannons(123456780000),
        lock_args.clone(),
    );

    data_loader
        .headers
        .insert(deposit_header.hash(), deposit_header.clone());
    data_loader
        .epoches
        .insert(deposit_header.hash(), deposit_epoch.clone());

    let input_cell_meta = CellMetaBuilder::from_cell_output(cell, Bytes::from(&[0; 8][..]))
        .out_point(previous_out_point.clone())
        .transaction_info(TransactionInfo {
            block_hash: deposit_header.hash(),
            block_number: deposit_header.number(),
            block_epoch: EpochNumberWithFraction::new(35, 554, 1000),
            index: 0,
        })
        .build();

    let resolved_inputs = vec![input_cell_meta];
    let mut resolved_cell_deps = vec![];

    let (output_cell, _) =
        gen_dao_cell(&mut data_loader, Capacity::shannons(1234567800), lock_args);

    let mut b = [0; 8];
    LittleEndian::write_u64(&mut b, 1554);
    let witness = WitnessArgs::new_builder().build();
    let builder = TransactionBuilder::default()
        .input(CellInput::new(previous_out_point, 0))
        .output(output_cell)
        .output_data(Bytes::from(&b[..]).pack())
        .header_dep(deposit_header.hash())
        .witness(witness.as_bytes().pack());
    let (tx, mut resolved_cell_deps2) = complete_tx(&mut data_loader, builder);
    let tx = sign_tx(tx, &privkey);
    for dep in resolved_cell_deps2.drain(..) {
        resolved_cell_deps.push(dep);
    }
    let rtx = ResolvedTransaction {
        transaction: tx,
        resolved_inputs,
        resolved_cell_deps,
        resolved_dep_groups: vec![],
    };

    let verify_result = TransactionScriptsVerifier::new(&rtx, &data_loader).verify(MAX_CYCLES);
    assert_error_eq!(
        verify_result.unwrap_err(),
        ScriptError::ValidationFailure(ERROR_INVALID_WITHDRAWING_CELL),
    );
}

#[test]
fn test_dao_too_many_output_cells() {
    let mut data_loader = DummyDataLoader::new();
    let (privkey, lock_args) = gen_lock();

    let (deposit_header, deposit_epoch) = gen_header(1554, 10000000, 35, 1000, 1000);
    let (withdraw_header, withdraw_epoch) = gen_header(2000610, 10001000, 575, 2000000, 1100);
    let (cell, previous_out_point) = gen_dao_cell(
        &mut data_loader,
        Capacity::shannons(1234567800 * 65),
        lock_args,
    );

    data_loader
        .headers
        .insert(deposit_header.hash(), deposit_header.clone());
    data_loader
        .headers
        .insert(withdraw_header.hash(), withdraw_header.clone());
    data_loader
        .epoches
        .insert(deposit_header.hash(), deposit_epoch.clone());
    data_loader
        .epoches
        .insert(withdraw_header.hash(), withdraw_epoch.clone());

    let mut b = [0; 8];
    LittleEndian::write_u64(&mut b, 1554);
    let input_cell_meta = CellMetaBuilder::from_cell_output(cell, Bytes::from(&b[..]))
        .out_point(previous_out_point.clone())
        .transaction_info(TransactionInfo {
            block_hash: withdraw_header.hash(),
            block_number: withdraw_header.number(),
            block_epoch: EpochNumberWithFraction::new(575, 610, 1100),
            index: 0,
        })
        .build();

    let resolved_inputs = vec![input_cell_meta];
    let mut resolved_cell_deps = vec![];

    let outputs = vec![cell_output_with_only_capacity(123468105678); 65];
    let outputs_data = vec![Bytes::new().pack(); 65];

    let mut b = [0; 8];
    LittleEndian::write_u64(&mut b, 1);
    let witness = WitnessArgs::new_builder()
        .type_(Bytes::from(&b[..]).pack())
        .build();
    let builder = TransactionBuilder::default()
        .input(CellInput::new(previous_out_point, 0x2003e8022a0002f3))
        .outputs(outputs)
        .outputs_data(outputs_data)
        .header_dep(withdraw_header.hash())
        .header_dep(deposit_header.hash())
        .witness(witness.as_bytes().pack());
    let (tx, mut resolved_cell_deps2) = complete_tx(&mut data_loader, builder);
    let tx = sign_tx(tx, &privkey);
    for dep in resolved_cell_deps2.drain(..) {
        resolved_cell_deps.push(dep);
    }
    let rtx = ResolvedTransaction {
        transaction: tx,
        resolved_inputs,
        resolved_cell_deps,
        resolved_dep_groups: vec![],
    };

    let verify_result = TransactionScriptsVerifier::new(&rtx, &data_loader).verify(MAX_CYCLES);
    assert_error_eq!(
        verify_result.unwrap_err(),
        ScriptError::ValidationFailure(ERROR_TOO_MANY_OUTPUT_CELLS),
    );
}

#[test]
fn test_dao_all_dao_actions() {
    let mut data_loader = DummyDataLoader::new();
    let (privkey, lock_args) = gen_lock();

    let (deposit_header, deposit_epoch) = gen_header(1554, 10000000, 35, 1000, 1000);
    let (withdraw_header, withdraw_epoch) = gen_header(2000610, 10001000, 575, 2000000, 1100);
    let (cell, previous_out_point) = gen_dao_cell(
        &mut data_loader,
        Capacity::shannons(123456780000),
        lock_args.clone(),
    );
    let (cell2, previous_out_point2) = gen_dao_cell(
        &mut data_loader,
        Capacity::shannons(1234567890),
        lock_args.clone(),
    );

    data_loader
        .headers
        .insert(deposit_header.hash(), deposit_header.clone());
    data_loader
        .headers
        .insert(withdraw_header.hash(), withdraw_header.clone());
    data_loader
        .epoches
        .insert(deposit_header.hash(), deposit_epoch.clone());
    data_loader
        .epoches
        .insert(withdraw_header.hash(), withdraw_epoch.clone());

    let mut b = [0; 8];
    LittleEndian::write_u64(&mut b, 1554);
    let input_cell_meta = CellMetaBuilder::from_cell_output(cell, Bytes::from(&b[..]))
        .out_point(previous_out_point.clone())
        .transaction_info(TransactionInfo {
            block_hash: withdraw_header.hash(),
            block_number: withdraw_header.number(),
            block_epoch: EpochNumberWithFraction::new(575, 610, 1100),
            index: 0,
        })
        .build();
    let input_cell_meta2 = CellMetaBuilder::from_cell_output(cell2, Bytes::from(&[0; 8][..]))
        .out_point(previous_out_point2.clone())
        .transaction_info(TransactionInfo {
            block_hash: deposit_header.hash(),
            block_number: deposit_header.number(),
            block_epoch: EpochNumberWithFraction::new(35, 554, 1000),
            index: 0,
        })
        .build();

    let resolved_inputs = vec![input_cell_meta, input_cell_meta2];
    let mut resolved_cell_deps = vec![];

    let (withdrawing_cell, _) =
        gen_dao_cell(&mut data_loader, Capacity::shannons(1234567890), lock_args);

    let mut b = [0; 8];
    LittleEndian::write_u64(&mut b, 1);
    let mut b2 = [0; 8];
    LittleEndian::write_u64(&mut b2, 1554);
    let witness = WitnessArgs::new_builder()
        .type_(Bytes::from(&b[..]).pack())
        .build();
    let type_ = Script::new_builder()
        .code_hash(dao_code_hash())
        .hash_type(ScriptHashType::Data.into())
        .build();
    let builder = TransactionBuilder::default()
        .input(CellInput::new(previous_out_point, 0x2003e8022a0002f3))
        .input(CellInput::new(previous_out_point2, 0))
        .output(cell_output_with_only_capacity(61734052839))
        .output(withdrawing_cell)
        .output(
            cell_output_with_only_capacity(61734052839)
                .as_builder()
                .type_(Some(type_).pack())
                .build(),
        )
        .output_data(Bytes::new().pack())
        .output_data(Bytes::from(&b2[..]).pack())
        .output_data(Bytes::from(&[0u8; 8][..]).pack())
        .header_dep(withdraw_header.hash())
        .header_dep(deposit_header.hash())
        .witness(witness.as_bytes().pack())
        .witness(WitnessArgs::new_builder().build().as_bytes().pack())
        .witness(WitnessArgs::new_builder().build().as_bytes().pack());
    let (tx, mut resolved_cell_deps2) = complete_tx(&mut data_loader, builder);
    let tx = sign_tx(tx, &privkey);
    for dep in resolved_cell_deps2.drain(..) {
        resolved_cell_deps.push(dep);
    }
    let rtx = ResolvedTransaction {
        transaction: tx,
        resolved_inputs,
        resolved_cell_deps,
        resolved_dep_groups: vec![],
    };

    let verify_result = TransactionScriptsVerifier::new(&rtx, &data_loader).verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}
