extern crate serde;
extern crate serde_json;

use neon::prelude::*;

use centipede::{
    grad_release::VEShare,
};
use curv::{GE, BigInt};
use curv::elliptic::curves::traits::{ECScalar, ECPoint};
use curv::arithmetic::traits::Converter;
use curv::elliptic::curves::secp256_k1::Secp256k1Scalar;
use hex;

use crate::SEGMENT_SIZE;
use centipede::grad_release::{FirstMessage, SegmentProof};

pub fn create_share(mut cx: FunctionContext) -> JsResult<JsString> {
    let expected_args = 2;
    if cx.len() != expected_args {
        return cx.throw_error("Invalid number of arguments");
    }

    let secret_hex: String = cx.argument::<JsString>(0)?.value();
    let secret_bn = BigInt::from_hex(&secret_hex);
    let secret: Secp256k1Scalar = ECScalar::from(&secret_bn);

    let enc_key_hex: String = cx.argument::<JsString>(1)?.value();
    let enc_key_bytes = hex::decode(&enc_key_hex)
        .expect(&format!("failed hex::decode of enc_key {}", &enc_key_hex));
    let enc_key: GE = ECPoint::from_bytes(enc_key_bytes.as_slice())
        .expect(&format!("failed deserialization of enc_key {}", &enc_key_hex));

    let (first_message, share) = VEShare::create(&secret, &enc_key, &SEGMENT_SIZE);

    Ok(cx.string(serde_json::to_string(&(first_message, share)).unwrap()))
}

pub fn verify_start(mut cx: FunctionContext) -> JsResult<JsBoolean> {
    let expected_args = 2;
    if cx.len() != expected_args {
        return cx.throw_error("Invalid number of arguments");
    }

    let first_message: FirstMessage = serde_json::from_str(&cx.argument::<JsString>(0)?.value())
        .expect("failed deserialization FirstMessage");

    let enc_key_hex: String = cx.argument::<JsString>(1)?.value();
    let enc_key_bytes = hex::decode(&enc_key_hex)
        .expect(&format!("failed hex::decode of enc_key {}", &enc_key_hex));
    let enc_key: GE = ECPoint::from_bytes(enc_key_bytes.as_slice())
        .expect(&format!("failed deserialization of enc_key {}", &enc_key_hex));

    let res = VEShare::start_verify(&first_message, &enc_key);

    match res {
        Err(_) => Ok(cx.boolean(false)),
        Ok(_) => Ok(cx.boolean(true)),
    }
}

pub fn segment_k_proof(mut cx: FunctionContext) -> JsResult<JsString> {
    let expected_args = 2;
    if cx.len() != expected_args {
        return cx.throw_error("Invalid number of arguments");
    }

    let share: VEShare = serde_json::from_str(&cx.argument::<JsString>(0)?.value())
        .expect("failed deserialization VEShare");

    let k: usize = cx.argument::<JsNumber>(1)?.value() as usize;

    let segment_proof = share.segment_k_proof(&k);

    Ok(cx.string(serde_json::to_string(&segment_proof).unwrap()))
}

pub fn verify_segment(mut cx: FunctionContext) -> JsResult<JsBoolean> {
    let expected_args = 3;
    if cx.len() != expected_args {
        return cx.throw_error("Invalid number of arguments");
    }

    let first_message: FirstMessage = serde_json::from_str(&cx.argument::<JsString>(0)?.value())
        .expect("failed deserialization FirstMessage");

    let segment_proof: SegmentProof = serde_json::from_str(&cx.argument::<JsString>(1)?.value())
        .expect("failed deserialization SegmentProof");

    let enc_key_hex: String = cx.argument::<JsString>(2)?.value();
    let enc_key_bytes = hex::decode(&enc_key_hex)
        .expect(&format!("failed hex::decode of enc_key {}", &enc_key_hex));
    let enc_key: GE = ECPoint::from_bytes(enc_key_bytes.as_slice())
        .expect(&format!("failed deserialization of enc_key {}", &enc_key_hex));

    let res = VEShare::verify_segment(&first_message, &segment_proof, &enc_key);

    match res {
        Err(_) => Ok(cx.boolean(false)),
        Ok(_) => Ok(cx.boolean(true)),
    }
}

pub fn extract_secret(mut cx: FunctionContext) -> JsResult<JsString> {
    let expected_args = 3;
    if cx.len() != expected_args {
        return cx.throw_error("Invalid number of arguments");
    }

    let first_message: FirstMessage = serde_json::from_str(&cx.argument::<JsString>(0)?.value())
        .expect("failed deserialization FirstMessage");

    let segment_proofs_js_array: Handle<JsArray> = cx.argument::<JsArray>(1)?;
    // Convert a JsArray to a Rust Vec
    let segment_proof_handle_vec: Vec<Handle<JsValue>> = segment_proofs_js_array.to_vec(&mut cx)?;
    let segment_proof_vec: Vec<SegmentProof> = segment_proof_handle_vec
        .into_iter()
        .map(|h| {
            serde_json::from_str(&h.to_string(&mut cx).unwrap().value())
                .expect("failed deserialization SegmentProof")
        })
        .collect::<Vec<SegmentProof>>();
    let segment_proofs = segment_proof_vec.as_slice();

    let dec_key_hex: String = cx.argument::<JsString>(2)?.value();
    let dec_key_bn = BigInt::from_hex(&dec_key_hex);
    let dec_key: Secp256k1Scalar = ECScalar::from(&dec_key_bn);

    let secret = VEShare::extract_secret(&first_message, segment_proofs, &dec_key)
        .expect("Failed extracting secret");

    Ok(cx.string(secret.to_big_int().to_hex()))
}