use super::{blake160, DummyDataLoader, MAX_CYCLES, MULTISIG_ALL_BIN, SECP256K1_DATA_BIN};
use ckb_crypto::secp::{Generator, Privkey};
use ckb_error::{assert_error_eq, Error};
use ckb_script::{ScriptError, TransactionScriptsVerifier};
use ckb_types::{
    bytes::Bytes,
    core::{
        cell::{CellMetaBuilder, ResolvedTransaction},
        Capacity, DepType, EpochNumberWithFraction, ScriptHashType, TransactionBuilder,
        TransactionView,
    },
    packed::{self, CellDep, CellInput, CellOutput, OutPoint, Script, WitnessArgs},
    prelude::*,
    H256,
};
use rand::{thread_rng, Rng};

const SIGNATURE_SIZE: usize = 65;

const ERROR_WITNESS_SIZE: i8 = -22;
const ERROR_INVALID_PUBKEYS_CNT: i8 = -42;
const ERROR_INVALID_THRESHOLD: i8 = -43;
const ERROR_INVALID_REQUIRE_FIRST_N: i8 = -44;
const ERROR_MULTSIG_SCRIPT_HASH: i8 = -51;
const ERROR_VERIFICATION: i8 = -52;
const ERROR_INCORRECT_SINCE_FLAG: i8 = -23;
const ERROR_INCORRECT_SINCE_VALUE: i8 = -24;

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
            ScriptError::ValidationFailure(ERROR_WITNESS_SIZE),
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
            ScriptError::ValidationFailure(ERROR_WITNESS_SIZE),
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
        .set_witnesses(vec![WitnessArgs::new_builder()
            .extra(Bytes::from(extract_witness).pack())
            .build()
            .as_bytes()
            .pack()])
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
                let witness = WitnessArgs::new_unchecked(Unpack::<Bytes>::unpack(
                    &tx.witnesses().get(0).unwrap(),
                ));
                let mut lock = multi_sign_script.to_vec();
                let lock_without_sig = {
                    let sig_len = keys.len() * SIGNATURE_SIZE;
                    let mut buf = lock.clone();
                    buf.resize(buf.len() + sig_len, 0);
                    buf
                };
                let witness_without_sig = witness
                    .clone()
                    .as_builder()
                    .lock(Bytes::from(lock_without_sig).pack())
                    .build();
                let len = witness_without_sig.as_bytes().len() as u64;
                blake2b.update(&len.to_le_bytes());
                blake2b.update(&witness_without_sig.as_bytes());
                (1..tx.witnesses().len()).for_each(|n| {
                    let witness: Bytes = tx.witnesses().get(n).unwrap().unpack();
                    let len = witness.len() as u64;
                    blake2b.update(&len.to_le_bytes());
                    blake2b.update(&witness);
                });
                blake2b.finalize(&mut message);
                let message = H256::from(message);
                keys.iter().for_each(|key| {
                    let sig = key.sign_recoverable(&message).expect("sign");
                    lock.extend_from_slice(&sig.serialize());
                });
                witness
                    .as_builder()
                    .lock(Bytes::from(lock).pack())
                    .build()
                    .as_bytes()
                    .pack()
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

#[test]
fn test_multisig_0_2_3_unlock_with_since() {
    let mut data_loader = DummyDataLoader::new();
    let keys = generate_keys(3);
    let since = 0x0000_0000_8888_8888u64;
    let multi_sign_script = gen_multi_sign_script(&keys, 2, 0);
    let args = {
        let mut buf = blake160(&multi_sign_script).to_vec();
        buf.extend(since.to_le_bytes().into_iter());
        Bytes::from(buf)
    };
    let raw_tx = gen_tx(&mut data_loader, args);
    {
        let tx = multi_sign_tx(raw_tx.clone(), &multi_sign_script, &[&keys[0], &keys[1]]);
        let verify_result = verify(&data_loader, &tx);
        assert_error_eq!(
            verify_result.unwrap_err(),
            ScriptError::ValidationFailure(ERROR_INCORRECT_SINCE_VALUE),
        );
    }
    {
        let inputs: Vec<CellInput> = raw_tx
            .inputs()
            .into_iter()
            .map(|i| i.as_builder().since((since - 1).pack()).build())
            .collect();
        let raw_tx = raw_tx.as_advanced_builder().set_inputs(inputs).build();
        let tx = multi_sign_tx(raw_tx, &multi_sign_script, &[&keys[1], &keys[2]]);
        let verify_result = verify(&data_loader, &tx);
        assert_error_eq!(
            verify_result.unwrap_err(),
            ScriptError::ValidationFailure(ERROR_INCORRECT_SINCE_VALUE),
        );
    }
    {
        let inputs: Vec<CellInput> = raw_tx
            .inputs()
            .into_iter()
            .map(|i| i.as_builder().since(0.pack()).build())
            .collect();
        let raw_tx = raw_tx.as_advanced_builder().set_inputs(inputs).build();
        let tx = multi_sign_tx(raw_tx, &multi_sign_script, &[&keys[1], &keys[2]]);
        let verify_result = verify(&data_loader, &tx);
        assert_error_eq!(
            verify_result.unwrap_err(),
            ScriptError::ValidationFailure(ERROR_INCORRECT_SINCE_VALUE),
        );
    }
    {
        // use a different flags
        let inputs: Vec<CellInput> = raw_tx
            .inputs()
            .into_iter()
            .map(|i| {
                i.as_builder()
                    .since((since | 0x2000_0000_0000_0000).pack())
                    .build()
            })
            .collect();
        let raw_tx = raw_tx.as_advanced_builder().set_inputs(inputs).build();
        let tx = multi_sign_tx(raw_tx, &multi_sign_script, &[&keys[1], &keys[2]]);
        let verify_result = verify(&data_loader, &tx);
        assert_error_eq!(
            verify_result.unwrap_err(),
            ScriptError::ValidationFailure(ERROR_INCORRECT_SINCE_FLAG),
        );
    }
    {
        let inputs: Vec<CellInput> = raw_tx
            .inputs()
            .into_iter()
            .map(|i| i.as_builder().since(since.pack()).build())
            .collect();
        let raw_tx = raw_tx.as_advanced_builder().set_inputs(inputs).build();
        let tx = multi_sign_tx(raw_tx, &multi_sign_script, &[&keys[1], &keys[2]]);
        verify(&data_loader, &tx).expect("pass verification");
    }
    {
        let inputs: Vec<CellInput> = raw_tx
            .inputs()
            .into_iter()
            .map(|i| i.as_builder().since((since + 1).pack()).build())
            .collect();
        let raw_tx = raw_tx.as_advanced_builder().set_inputs(inputs).build();
        let tx = multi_sign_tx(raw_tx, &multi_sign_script, &[&keys[1], &keys[2]]);
        verify(&data_loader, &tx).expect("pass verification");
    }
}

#[test]
fn test_multisig_0_2_3_unlock_with_since_epoch() {
    let mut data_loader = DummyDataLoader::new();
    let keys = generate_keys(3);
    let since_epoch = EpochNumberWithFraction::new(200, 5, 100);
    let since = 0x2000_0000_0000_0000u64 + since_epoch.full_value();
    let multi_sign_script = gen_multi_sign_script(&keys, 2, 0);
    let args = {
        let mut buf = blake160(&multi_sign_script).to_vec();
        buf.extend(since.to_le_bytes().into_iter());
        Bytes::from(buf)
    };
    let raw_tx = gen_tx(&mut data_loader, args);
    {
        let tx = multi_sign_tx(raw_tx.clone(), &multi_sign_script, &[&keys[0], &keys[1]]);
        let verify_result = verify(&data_loader, &tx);
        assert_error_eq!(
            verify_result.unwrap_err(),
            ScriptError::ValidationFailure(ERROR_INCORRECT_SINCE_FLAG),
        );
    }
    {
        let epoch = EpochNumberWithFraction::new(200, 2, 200);
        let inputs: Vec<CellInput> = raw_tx
            .inputs()
            .into_iter()
            .map(|i| {
                i.as_builder()
                    .since((0x2000_0000_0000_0000u64 + epoch.full_value()).pack())
                    .build()
            })
            .collect();
        let raw_tx = raw_tx.as_advanced_builder().set_inputs(inputs).build();
        let tx = multi_sign_tx(raw_tx, &multi_sign_script, &[&keys[1], &keys[2]]);
        let verify_result = verify(&data_loader, &tx);
        assert_error_eq!(
            verify_result.unwrap_err(),
            ScriptError::ValidationFailure(ERROR_INCORRECT_SINCE_VALUE),
        );
    }
    {
        let inputs: Vec<CellInput> = raw_tx
            .inputs()
            .into_iter()
            .map(|i| i.as_builder().since(0.pack()).build())
            .collect();
        let raw_tx = raw_tx.as_advanced_builder().set_inputs(inputs).build();
        let tx = multi_sign_tx(raw_tx, &multi_sign_script, &[&keys[1], &keys[2]]);
        let verify_result = verify(&data_loader, &tx);
        assert_error_eq!(
            verify_result.unwrap_err(),
            ScriptError::ValidationFailure(ERROR_INCORRECT_SINCE_FLAG),
        );
    }
    {
        let epoch = EpochNumberWithFraction::new(200, 1, 600);
        let inputs: Vec<CellInput> = raw_tx
            .inputs()
            .into_iter()
            .map(|i| {
                i.as_builder()
                    .since((0x2000_0000_0000_0000u64 + epoch.full_value()).pack())
                    .build()
            })
            .collect();
        let raw_tx = raw_tx.as_advanced_builder().set_inputs(inputs).build();
        let tx = multi_sign_tx(raw_tx, &multi_sign_script, &[&keys[1], &keys[2]]);
        let verify_result = verify(&data_loader, &tx);
        assert_error_eq!(
            verify_result.unwrap_err(),
            ScriptError::ValidationFailure(ERROR_INCORRECT_SINCE_VALUE),
        );
    }
    {
        let epoch = EpochNumberWithFraction::new(200, 6, 50);
        let inputs: Vec<CellInput> = raw_tx
            .inputs()
            .into_iter()
            .map(|i| {
                i.as_builder()
                    .since((0x2000_0000_0000_0000u64 + epoch.full_value()).pack())
                    .build()
            })
            .collect();
        let raw_tx = raw_tx.as_advanced_builder().set_inputs(inputs).build();
        let tx = multi_sign_tx(raw_tx, &multi_sign_script, &[&keys[1], &keys[2]]);
        verify(&data_loader, &tx).expect("pass verification");
    }
    {
        let epoch = EpochNumberWithFraction::new(200, 1, 2);
        let inputs: Vec<CellInput> = raw_tx
            .inputs()
            .into_iter()
            .map(|i| {
                i.as_builder()
                    .since((0x2000_0000_0000_0000u64 + epoch.full_value()).pack())
                    .build()
            })
            .collect();
        let raw_tx = raw_tx.as_advanced_builder().set_inputs(inputs).build();
        let tx = multi_sign_tx(raw_tx, &multi_sign_script, &[&keys[1], &keys[2]]);
        verify(&data_loader, &tx).expect("pass verification");
    }
    {
        let epoch = EpochNumberWithFraction::new(200, 6, 100);
        let inputs: Vec<CellInput> = raw_tx
            .inputs()
            .into_iter()
            .map(|i| {
                i.as_builder()
                    .since((0x2000_0000_0000_0000u64 + epoch.full_value()).pack())
                    .build()
            })
            .collect();
        let raw_tx = raw_tx.as_advanced_builder().set_inputs(inputs).build();
        let tx = multi_sign_tx(raw_tx, &multi_sign_script, &[&keys[1], &keys[2]]);
        verify(&data_loader, &tx).expect("pass verification");
    }
    {
        let inputs: Vec<CellInput> = raw_tx
            .inputs()
            .into_iter()
            .map(|i| i.as_builder().since(since.pack()).build())
            .collect();
        let raw_tx = raw_tx.as_advanced_builder().set_inputs(inputs).build();
        let tx = multi_sign_tx(raw_tx, &multi_sign_script, &[&keys[1], &keys[2]]);
        verify(&data_loader, &tx).expect("pass verification");
    }
    {
        let inputs: Vec<CellInput> = raw_tx
            .inputs()
            .into_iter()
            .map(|i| i.as_builder().since((since + 1).pack()).build())
            .collect();
        let raw_tx = raw_tx.as_advanced_builder().set_inputs(inputs).build();
        let tx = multi_sign_tx(raw_tx, &multi_sign_script, &[&keys[1], &keys[2]]);
        verify(&data_loader, &tx).expect("pass verification");
    }
}

#[test]
fn test_genesis_time_locked_cell() {
    // Test against ckb1qyqxs3hhwx2ttqcrk2yk2nsgqteglvfjt4hsjpzgxs,5200,2020-02-09
    let mut data_loader = DummyDataLoader::new();

    let args = {
        let mut args_buffer = vec![0u8; 28];
        faster_hex::hex_decode(
            "6a7d3560d87009c5dcfdc76a4ac60d8a47bb1f312b02008403080720".as_bytes(),
            args_buffer.as_mut_slice(),
        )
        .unwrap();
        Bytes::from(args_buffer)
    };
    let keys = {
        let mut privkey_buffer = vec![0u8; 32];
        faster_hex::hex_decode(
            "41a0bf7d6102fed4183acb0affa72cfb31726d9900964c7cb363632a26ecca18".as_bytes(),
            privkey_buffer.as_mut_slice(),
        )
        .unwrap();
        vec![Privkey::from_slice(privkey_buffer.as_slice())]
    };

    let multi_sign_script = gen_multi_sign_script(&keys, 1, 0);
    let raw_tx = gen_tx(&mut data_loader, args);

    // locked until 2020-02-09
    // 555 + 900/1800
    {
        let epoch = EpochNumberWithFraction::new(555, 899, 1800);
        let inputs: Vec<CellInput> = raw_tx
            .inputs()
            .into_iter()
            .map(|i| {
                i.as_builder()
                    .since((0x2000_0000_0000_0000u64 + epoch.full_value()).pack())
                    .build()
            })
            .collect();
        let raw_tx = raw_tx.as_advanced_builder().set_inputs(inputs).build();
        let tx = multi_sign_tx(raw_tx, &multi_sign_script, &[&keys[0]]);
        let verify_result = verify(&data_loader, &tx);
        assert_error_eq!(
            verify_result.unwrap_err(),
            ScriptError::ValidationFailure(ERROR_INCORRECT_SINCE_VALUE),
        );
    }
    {
        let epoch = EpochNumberWithFraction::new(555, 900, 1800);
        let inputs: Vec<CellInput> = raw_tx
            .inputs()
            .into_iter()
            .map(|i| {
                i.as_builder()
                    .since((0x2000_0000_0000_0000u64 + epoch.full_value()).pack())
                    .build()
            })
            .collect();
        let raw_tx = raw_tx.as_advanced_builder().set_inputs(inputs).build();
        let tx = multi_sign_tx(raw_tx, &multi_sign_script, &[&keys[0]]);
        verify(&data_loader, &tx).expect("pass verification");
    }
}

fn gen_multi_sign_script(keys: &[Privkey], threshold: u8, require_first_n: u8) -> Bytes {
    let pubkeys = keys
        .iter()
        .map(|key| key.pubkey().unwrap())
        .collect::<Vec<_>>();
    let mut script = vec![0u8, require_first_n, threshold, pubkeys.len() as u8];
    pubkeys.iter().for_each(|pubkey| {
        script.extend_from_slice(&blake160(&pubkey.serialize()));
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
        .hash_type(ScriptHashType::Data.into())
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
                .dep_type(DepType::Code.into())
                .build(),
        )
        .cell_dep(
            CellDep::new_builder()
                .out_point(secp256k1_data_out_point)
                .dep_type(DepType::Code.into())
                .build(),
        )
        .output(CellOutput::new_builder().capacity(capacity.pack()).build())
        .output_data(Bytes::new().pack());
    if extra_inputs > 0 {
        let mut extra_inputs_tx_builder = tx_builder.clone();
        extra_inputs_tx_builder =
            extra_inputs_tx_builder.witness(WitnessArgs::new_builder().build().as_bytes().pack());
        let mut rng = thread_rng();
        for i in 1..=extra_inputs {
            let extra_out_point = OutPoint::new(previous_tx_hash.clone(), i);
            dummy.cells.insert(
                extra_out_point.clone(),
                (previous_output_cell.clone(), Bytes::new()),
            );
            let mut random_extra = [0u8; 32];
            rng.fill(&mut random_extra);
            extra_inputs_tx_builder = extra_inputs_tx_builder
                .input(CellInput::new(extra_out_point, 0))
                .witness(
                    WitnessArgs::new_builder()
                        .extra(Bytes::from(random_extra.to_vec()).pack())
                        .build()
                        .as_bytes()
                        .pack(),
                );
        }
        extra_inputs_tx_builder.build()
    } else {
        tx_builder
            .witness(WitnessArgs::new_builder().build().as_bytes().pack())
            .build()
    }
}

fn gen_tx(dummy: &mut DummyDataLoader, lock_args: Bytes) -> TransactionView {
    gen_tx_with_extra_inputs(dummy, lock_args, 0)
}

fn build_resolved_tx(data_loader: &DummyDataLoader, tx: &TransactionView) -> ResolvedTransaction {
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
    let resolved_inputs = tx
        .inputs()
        .into_iter()
        .map(|input| {
            let previous_out_point = input.previous_output();
            let (input_output, input_data) = data_loader.cells.get(&previous_out_point).unwrap();
            CellMetaBuilder::from_cell_output(input_output.to_owned(), input_data.to_owned())
                .out_point(previous_out_point)
                .build()
        })
        .collect::<Vec<_>>();
    ResolvedTransaction {
        transaction: tx.clone(),
        resolved_cell_deps,
        resolved_inputs,
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
