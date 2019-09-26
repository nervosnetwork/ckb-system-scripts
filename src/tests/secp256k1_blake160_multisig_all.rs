use super::{blake160, DummyDataLoader, MAX_CYCLES, MULTISIG_ALL_BIN, SECP256K1_DATA_BIN};
use ckb_crypto::secp::{Generator, Privkey};
use ckb_error::{assert_error_eq, Error};
use ckb_script::{ScriptError, TransactionScriptsVerifier};
use ckb_types::{
    bytes::Bytes,
    core::{
        cell::{CellMetaBuilder, ResolvedTransaction},
        Capacity, DepType, ScriptHashType, TransactionBuilder, TransactionView,
    },
    packed::{self, CellDep, CellInput, CellOutput, OutPoint, Script},
    prelude::*,
    H256,
};
use rand::{thread_rng, Rng};

const ERROR_WITNESS_TOO_SHORT: i8 = -23;
const ERROR_INVALID_PUBKEYS_CNT: i8 = -24;
const ERROR_INVALID_THRESHOLD: i8 = -25;
const ERROR_INVALID_REQUIRE_FIRST_N: i8 = -26;
const ERROR_MULTSIG_SCRIPT_HASH: i8 = -31;
const ERROR_VERIFICATION: i8 = -32;

#[test]
fn test_multisig_script_hash() {
    let mut data_loader = DummyDataLoader::new();
    let keys = generate_keys(3);
    let multi_sign_script = gen_multi_sign_script(&keys, 2, 0);
    let args = blake160(&multi_sign_script);
    let raw_tx = gen_tx(&mut data_loader, args);
    {
        let wrong_multi_sign_script = gen_multi_sign_script(&keys, 2, 1);
        let tx = multi_sign_tx(
            raw_tx.clone(),
            &wrong_multi_sign_script,
            &[&keys[0], &keys[1]],
        );
        let verify_result = verify(&data_loader, &tx);
        assert_error_eq!(
            verify_result.unwrap_err(),
            ScriptError::ValidationFailure(ERROR_MULTSIG_SCRIPT_HASH),
        );
    }
}

#[test]
fn test_invalid_flags() {
    let mut data_loader = DummyDataLoader::new();
    let keys = generate_keys(3);
    let multi_sign_script = gen_multi_sign_script(&keys, 2, 0);
    let args = blake160(&multi_sign_script);
    let raw_tx = gen_tx(&mut data_loader, args);
    {
        let wrong_multi_sign_script = gen_multi_sign_script(&vec![], 2, 0);
        let tx = multi_sign_tx(
            raw_tx.clone(),
            &wrong_multi_sign_script,
            &[&keys[0], &keys[1]],
        );
        let verify_result = verify(&data_loader, &tx);
        assert_error_eq!(
            verify_result.unwrap_err(),
            ScriptError::ValidationFailure(ERROR_INVALID_PUBKEYS_CNT),
        );
    }
    {
        let wrong_multi_sign_script = gen_multi_sign_script(&keys, 4, 0);
        let tx = multi_sign_tx(
            raw_tx.clone(),
            &wrong_multi_sign_script,
            &[&keys[0], &keys[1]],
        );
        let verify_result = verify(&data_loader, &tx);
        assert_error_eq!(
            verify_result.unwrap_err(),
            ScriptError::ValidationFailure(ERROR_INVALID_THRESHOLD),
        );
    }
    {
        let wrong_multi_sign_script = gen_multi_sign_script(&keys, 2, 3);
        let tx = multi_sign_tx(
            raw_tx.clone(),
            &wrong_multi_sign_script,
            &[&keys[0], &keys[1]],
        );
        let verify_result = verify(&data_loader, &tx);
        assert_error_eq!(
            verify_result.unwrap_err(),
            ScriptError::ValidationFailure(ERROR_INVALID_REQUIRE_FIRST_N),
        );
    }
}

#[test]
fn test_multisig_0_2_3_unlock() {
    let mut data_loader = DummyDataLoader::new();
    let keys = generate_keys(3);
    let multi_sign_script = gen_multi_sign_script(&keys, 2, 0);
    let args = blake160(&multi_sign_script);
    let raw_tx = gen_tx(&mut data_loader, args);
    {
        let tx = multi_sign_tx(raw_tx.clone(), &multi_sign_script, &[&keys[0], &keys[1]]);
        verify(&data_loader, &tx).expect("pass verification");
    }
    {
        let tx = multi_sign_tx(raw_tx.clone(), &multi_sign_script, &[&keys[1], &keys[0]]);
        verify(&data_loader, &tx).expect("pass verification");
    }
    {
        let tx = multi_sign_tx(raw_tx.clone(), &multi_sign_script, &[&keys[0], &keys[2]]);
        verify(&data_loader, &tx).expect("pass verification");
    }
    {
        let tx = multi_sign_tx(raw_tx.clone(), &multi_sign_script, &[&keys[1], &keys[2]]);
        verify(&data_loader, &tx).expect("pass verification");
    }

    {
        let tx = multi_sign_tx(raw_tx.clone(), &multi_sign_script, &[&keys[0]]);
        let verify_result = verify(&data_loader, &tx);
        assert_error_eq!(
            verify_result.unwrap_err(),
            ScriptError::ValidationFailure(ERROR_WITNESS_TOO_SHORT),
        );
    }
    {
        let tx = multi_sign_tx(
            raw_tx.clone(),
            &multi_sign_script,
            &[&keys[0], &keys[1], &keys[2]],
        );
        let verify_result = verify(&data_loader, &tx);
        assert_error_eq!(
            verify_result.unwrap_err(),
            ScriptError::ValidationFailure(ERROR_VERIFICATION),
        );
    }

    let wrong_keys = generate_keys(2);
    {
        let tx = multi_sign_tx(
            raw_tx.clone(),
            &multi_sign_script,
            &[&wrong_keys[0], &wrong_keys[1]],
        );
        let verify_result = verify(&data_loader, &tx);
        assert_error_eq!(
            verify_result.unwrap_err(),
            ScriptError::ValidationFailure(ERROR_VERIFICATION),
        );
    }
    {
        let tx = multi_sign_tx(
            raw_tx.clone(),
            &multi_sign_script,
            &[&keys[0], &wrong_keys[0]],
        );
        let verify_result = verify(&data_loader, &tx);
        assert_error_eq!(
            verify_result.unwrap_err(),
            ScriptError::ValidationFailure(ERROR_VERIFICATION),
        );
    }
}

#[test]
fn test_multisig_1_2_3_unlock() {
    let mut data_loader = DummyDataLoader::new();
    let keys = generate_keys(3);
    let multi_sign_script = gen_multi_sign_script(&keys, 2, 1);
    let args = blake160(&multi_sign_script);
    let tx = gen_tx(&mut data_loader, args);
    {
        let tx = multi_sign_tx(tx.clone(), &multi_sign_script, &[&keys[0], &keys[1]]);
        verify(&data_loader, &tx).expect("pass verification");
    }
    {
        let tx = multi_sign_tx(tx.clone(), &multi_sign_script, &[&keys[1], &keys[0]]);
        verify(&data_loader, &tx).expect("pass verification");
    }
    {
        let tx = multi_sign_tx(tx.clone(), &multi_sign_script, &[&keys[0], &keys[2]]);
        verify(&data_loader, &tx).expect("pass verification");
    }
    {
        let tx = multi_sign_tx(tx.clone(), &multi_sign_script, &[&keys[1], &keys[2]]);
        let verify_result = verify(&data_loader, &tx);
        assert_error_eq!(
            verify_result.unwrap_err(),
            ScriptError::ValidationFailure(ERROR_VERIFICATION),
        );
    }
}

#[test]
fn test_multisig_1_2_3_with_extra_witness_unlock() {
    let mut data_loader = DummyDataLoader::new();
    let keys = generate_keys(3);
    let multi_sign_script = gen_multi_sign_script(&keys, 2, 1);
    let args = blake160(&multi_sign_script);
    let tx = gen_tx(&mut data_loader, args);
    let extract_witness = vec![1, 2, 3, 4];
    let tx = tx
        .as_advanced_builder()
        .set_witnesses(vec![Bytes::from(extract_witness).pack()])
        .build();
    {
        let tx = multi_sign_tx(tx.clone(), &multi_sign_script, &[&keys[0], &keys[1]]);
        verify(&data_loader, &tx).expect("pass verification");
    }
    {
        let tx = multi_sign_tx(tx.clone(), &multi_sign_script, &[&keys[1], &keys[0]]);
        verify(&data_loader, &tx).expect("pass verification");
    }
    {
        let tx = multi_sign_tx(tx.clone(), &multi_sign_script, &[&keys[0], &keys[2]]);
        verify(&data_loader, &tx).expect("pass verification");
    }
    {
        let tx = multi_sign_tx(tx.clone(), &multi_sign_script, &[&keys[1], &keys[2]]);
        let verify_result = verify(&data_loader, &tx);
        assert_error_eq!(
            verify_result.unwrap_err(),
            ScriptError::ValidationFailure(ERROR_VERIFICATION),
        );
    }
}

#[test]
fn test_multisig_1_2_3_with_multiple_inputs_unlock() {
    let mut data_loader = DummyDataLoader::new();
    let keys = generate_keys(3);
    let multi_sign_script = gen_multi_sign_script(&keys, 2, 1);
    let args = blake160(&multi_sign_script);
    let tx = gen_tx_with_extra_inputs(&mut data_loader, args, 1);
    {
        let tx = multi_sign_tx(tx.clone(), &multi_sign_script, &[&keys[0], &keys[1]]);
        verify(&data_loader, &tx).expect("pass verification");
    }
    {
        let tx = multi_sign_tx(tx.clone(), &multi_sign_script, &[&keys[1], &keys[0]]);
        verify(&data_loader, &tx).expect("pass verification");
    }
    {
        let tx = multi_sign_tx(tx.clone(), &multi_sign_script, &[&keys[0], &keys[2]]);
        verify(&data_loader, &tx).expect("pass verification");
    }
    {
        let tx = multi_sign_tx(tx.clone(), &multi_sign_script, &[&keys[1], &keys[2]]);
        let verify_result = verify(&data_loader, &tx);
        assert_error_eq!(
            verify_result.unwrap_err(),
            ScriptError::ValidationFailure(ERROR_VERIFICATION),
        );
    }
}

#[test]
fn test_multisig_0_1_1_unlock() {
    let mut data_loader = DummyDataLoader::new();
    let keys = generate_keys(1);
    let multi_sign_script = gen_multi_sign_script(&keys, 1, 0);
    let args = blake160(&multi_sign_script);
    let raw_tx = gen_tx(&mut data_loader, args);
    {
        let tx = multi_sign_tx(raw_tx.clone(), &multi_sign_script, &[&keys[0]]);
        verify(&data_loader, &tx).expect("pass verification");
    }
    let wrong_keys = generate_keys(1);
    {
        let tx = multi_sign_tx(raw_tx.clone(), &multi_sign_script, &[&wrong_keys[0]]);
        let verify_result = verify(&data_loader, &tx);
        assert_error_eq!(
            verify_result.unwrap_err(),
            ScriptError::ValidationFailure(ERROR_VERIFICATION),
        );
    }
}

#[test]
fn test_multisig_0_2_2_unlock() {
    let mut data_loader = DummyDataLoader::new();
    let keys = generate_keys(2);
    let multi_sign_script = gen_multi_sign_script(&keys, 2, 0);
    let args = blake160(&multi_sign_script);
    let raw_tx = gen_tx(&mut data_loader, args);
    {
        let tx = multi_sign_tx(raw_tx.clone(), &multi_sign_script, &[&keys[0], &keys[1]]);
        verify(&data_loader, &tx).expect("pass verification");
    }
    let wrong_keys = generate_keys(2);
    {
        let tx = multi_sign_tx(
            raw_tx.clone(),
            &multi_sign_script,
            &[&keys[0], &wrong_keys[1]],
        );
        let verify_result = verify(&data_loader, &tx);
        assert_error_eq!(
            verify_result.unwrap_err(),
            ScriptError::ValidationFailure(ERROR_VERIFICATION),
        );
    }
}

fn multi_sign_tx(
    tx: TransactionView,
    multi_sign_script: &Bytes,
    keys: &[&Privkey],
) -> TransactionView {
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
                let mut signed_witness = Bytes::from(multi_sign_script.to_vec().as_slice());
                keys.iter().for_each(|key| {
                    let sig = key.sign_recoverable(&message).expect("sign");
                    signed_witness.extend_from_slice(&sig.serialize());
                });
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

fn gen_multi_sign_script(keys: &[Privkey], threshold: u8, require_first_n: u8) -> Bytes {
    let pubkeys = keys
        .iter()
        .map(|key| key.pubkey().unwrap())
        .collect::<Vec<_>>();
    let mut script = vec![0u8, require_first_n, threshold, pubkeys.len() as u8];
    pubkeys.iter().for_each(|pubkey| {
        script.extend_from_slice(&pubkey.serialize());
    });
    script.into()
}

fn gen_tx_with_extra_inputs(
    dummy: &mut DummyDataLoader,
    lock_args: Bytes,
    extra_inputs: u32,
) -> TransactionView {
    let previous_tx_hash = {
        let mut rng = thread_rng();
        let mut buf = [0u8; 32];
        rng.fill(&mut buf);
        buf.pack()
    };
    let previous_index = 0;
    let capacity = Capacity::shannons(42);
    let previous_out_point = OutPoint::new(previous_tx_hash.clone(), previous_index);
    let contract_tx_hash = {
        let mut rng = thread_rng();
        let mut buf = [0u8; 32];
        rng.fill(&mut buf);
        buf.pack()
    };
    let contract_index = 0;
    let contract_out_point = OutPoint::new(contract_tx_hash.clone(), contract_index);
    // dep contract code
    let dep_cell = CellOutput::new_builder()
        .capacity(
            Capacity::bytes(MULTISIG_ALL_BIN.len())
                .expect("script capacity")
                .pack(),
        )
        .build();
    let dep_cell_data_hash = CellOutput::calc_data_hash(&MULTISIG_ALL_BIN);
    dummy.cells.insert(
        contract_out_point.clone(),
        (dep_cell, MULTISIG_ALL_BIN.clone()),
    );
    // secp256k1 data
    let secp256k1_data_out_point = {
        let tx_hash = {
            let mut rng = thread_rng();
            let mut buf = [0u8; 32];
            rng.fill(&mut buf);
            buf.pack()
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
        (previous_output_cell.clone(), Bytes::new()),
    );
    let tx_builder = TransactionBuilder::default()
        .input(CellInput::new(previous_out_point.clone(), 0))
        .cell_dep(
            CellDep::new_builder()
                .out_point(contract_out_point)
                .dep_type(DepType::Code.pack())
                .build(),
        )
        .cell_dep(
            CellDep::new_builder()
                .out_point(secp256k1_data_out_point)
                .dep_type(DepType::Code.pack())
                .build(),
        )
        .output(CellOutput::new_builder().capacity(capacity.pack()).build())
        .output_data(Bytes::new().pack());
    if extra_inputs > 0 {
        let mut extra_inputs_tx_builder = tx_builder.clone();
        extra_inputs_tx_builder = extra_inputs_tx_builder.witness(Bytes::new().pack());
        let mut rng = thread_rng();
        for i in 0..extra_inputs {
            let extra_out_point = OutPoint::new(previous_tx_hash.clone(), i);
            dummy.cells.insert(
                extra_out_point.clone(),
                (previous_output_cell.clone(), Bytes::new()),
            );
            let mut random_extra_witness = [0u8; 32];
            rng.fill(&mut random_extra_witness);
            extra_inputs_tx_builder = extra_inputs_tx_builder
                .input(CellInput::new(extra_out_point, 0))
                .witness(Bytes::from(random_extra_witness.to_vec()).pack());
        }
        extra_inputs_tx_builder.build()
    } else {
        tx_builder.witness(Bytes::new().pack()).build()
    }
}

fn gen_tx(dummy: &mut DummyDataLoader, lock_args: Bytes) -> TransactionView {
    gen_tx_with_extra_inputs(dummy, lock_args, 0)
}

fn build_resolved_tx(data_loader: &DummyDataLoader, tx: &TransactionView) -> ResolvedTransaction {
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
        transaction: tx.clone(),
        resolved_cell_deps,
        resolved_inputs: vec![input_cell],
        resolved_dep_groups: vec![],
    }
}

fn generate_keys(n: usize) -> Vec<Privkey> {
    let mut keys = Vec::with_capacity(n);
    for _ in 0..n {
        keys.push(Generator::random_privkey());
    }

    keys
}

fn verify(data_loader: &DummyDataLoader, tx: &TransactionView) -> Result<u64, Error> {
    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    TransactionScriptsVerifier::new(&resolved_tx, data_loader).verify(MAX_CYCLES)
}
