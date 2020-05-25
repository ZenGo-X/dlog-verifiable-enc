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

    println!("create_share: #1");
    let secret_hex: String = cx.argument::<JsString>(0)?.value();
    println!("create_share: #2");
    let secret_bn = BigInt::from_hex(&secret_hex);
    println!("create_share: #3");
    let secret: Secp256k1Scalar = ECScalar::from(&secret_bn);

    println!("create_share: #4");
    let enc_key_hex: String = cx.argument::<JsString>(1)?.value();
    println!("create_share: #5");
    let enc_key_bytes = hex::decode(&enc_key_hex)
        .expect(&format!("failed hex::decode of enc_key {}", &enc_key_hex));
    println!("create_share: #6");
    let enc_key: GE = ECPoint::from_bytes(enc_key_bytes.as_slice())
        .expect(&format!("failed deserialization of enc_key {}", &enc_key_hex));

    println!("create_share: #7");
    let (first_message, share) = VEShare::create(&secret, &enc_key, &SEGMENT_SIZE);

    println!("create_share: #8");
    Ok(cx.string(serde_json::to_string(&(first_message, share)).unwrap()))
}

pub fn verify_start(mut cx: FunctionContext) -> JsResult<JsBoolean> {
    let expected_args = 2;
    if cx.len() != expected_args {
        return cx.throw_error("Invalid number of arguments");
    }

    println!("verify_start: #1");
    let first_message: FirstMessage = serde_json::from_str(&cx.argument::<JsString>(0)?.value())
        .expect("failed deserialization FirstMessage");

    println!("verify_start: #2");
    let enc_key_hex: String = cx.argument::<JsString>(1)?.value();
    println!("verify_start: #3");
    let enc_key_bytes = hex::decode(&enc_key_hex)
        .expect(&format!("failed hex::decode of enc_key {}", &enc_key_hex));
    println!("verify_start: #4");
    let enc_key: GE = ECPoint::from_bytes(enc_key_bytes.as_slice())
        .expect(&format!("failed deserialization of enc_key {}", &enc_key_hex));

    println!("verify_start: #5");
    let res = VEShare::start_verify(&first_message, &enc_key);

    println!("verify_start: #6");
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

    println!("segment_k_proof: #1");
    let share: VEShare = serde_json::from_str(&cx.argument::<JsString>(0)?.value())
        .expect("failed deserialization VEShare");

    println!("segment_k_proof: #2");
    let k: usize = cx.argument::<JsNumber>(1)?.value() as usize;

    println!("segment_k_proof: #3");
    let segment_proof = share.segment_k_proof(&k);

    println!("segment_k_proof: #4");
    Ok(cx.string(serde_json::to_string(&segment_proof).unwrap()))
}

pub fn verify_segment(mut cx: FunctionContext) -> JsResult<JsBoolean> {
    let expected_args = 3;
    if cx.len() != expected_args {
        return cx.throw_error("Invalid number of arguments");
    }

    println!("verify_segment: #1");
    let first_message: FirstMessage = serde_json::from_str(&cx.argument::<JsString>(0)?.value())
        .expect("failed deserialization FirstMessage");

    println!("verify_segment: #2");
    let segment_proof: SegmentProof = serde_json::from_str(&cx.argument::<JsString>(1)?.value())
        .expect("failed deserialization SegmentProof");

    println!("verify_segment: #3");
    let enc_key_hex: String = cx.argument::<JsString>(2)?.value();
    println!("verify_segment: #4");
    let enc_key_bytes = hex::decode(&enc_key_hex)
        .expect(&format!("failed hex::decode of enc_key {}", &enc_key_hex));
    println!("verify_segment: #5");
    let enc_key: GE = ECPoint::from_bytes(enc_key_bytes.as_slice())
        .expect(&format!("failed deserialization of enc_key {}", &enc_key_hex));

    println!("verify_segment: #6");
    let res = VEShare::verify_segment(&first_message, &segment_proof, &enc_key);

    println!("verify_segment: #7");
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

    println!("extract_secret: #1");
    let first_message: FirstMessage = serde_json::from_str(&cx.argument::<JsString>(0)?.value())
        .expect("failed deserialization FirstMessage");

    println!("extract_secret: #2");
    let segment_proofs_js_array: Handle<JsArray> = cx.argument::<JsArray>(1)?;
    // Convert a JsArray to a Rust Vec
    println!("extract_secret: #3");
    let segment_proof_handle_vec: Vec<Handle<JsValue>> = segment_proofs_js_array.to_vec(&mut cx)?;
    println!("extract_secret: #4");
    let segment_proof_vec: Vec<SegmentProof> = segment_proof_handle_vec
        .into_iter()
        .map(|h| {
            serde_json::from_str(&h.to_string(&mut cx).unwrap().value())
                .expect("failed deserialization SegmentProof")
        })
        .collect::<Vec<SegmentProof>>();
    let segment_proofs = segment_proof_vec.as_slice();

    println!("extract_secret: #5");
    let dec_key_hex: String = cx.argument::<JsString>(2)?.value();
    println!("extract_secret: #6");
    let dec_key_bn = BigInt::from_hex(&dec_key_hex);
    println!("extract_secret: dec_key_hex = {}", dec_key_hex);
    let dec_key: Secp256k1Scalar = ECScalar::from(&dec_key_bn);
    println!("extract_secret: post dec_key_hex");

    let secret = VEShare::extract_secret(&first_message, segment_proofs, &dec_key)
        .expect("Failed extracting secret");

    Ok(cx.string(secret.to_big_int().to_hex()))
}