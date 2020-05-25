extern crate serde;
extern crate serde_json;

use neon::prelude::*;

use centipede::{
    juggling::{
        segmentation::Msegmentation,
        proof_system::{Helgamalsegmented, Witness, Proof},
    }
};
use curv::{GE, BigInt};
use curv::elliptic::curves::traits::{ECScalar, ECPoint};
use curv::arithmetic::traits::Converter;
use curv::elliptic::curves::secp256_k1::Secp256k1Scalar;
use hex;

use crate::SEGMENT_SIZE;
use crate::NUM_OF_SEGMENTS;

#[allow(non_snake_case)]
pub fn encrypt(mut cx: FunctionContext) -> JsResult<JsString> {
    let expected_args = 2;
    if cx.len() != expected_args {
        return cx.throw_error("Invalid number of arguments");
    }

    println!("encrypt: #1");
    let public_key_hex: String = cx.argument::<JsString>(0)?.value();
    println!("encrypt: #2");
    let public_key_bytes = hex::decode(&public_key_hex)
        .expect(&format!("failed hex::decode of public_key {}", &public_key_hex));
    println!("encrypt: #3");
    let public_key: GE = ECPoint::from_bytes(public_key_bytes.as_slice())
        .expect(&format!("failed deserialization of public_key {}", &public_key_hex));

    println!("encrypt: #4");
    let secret_hex: String = cx.argument::<JsString>(1)?.value();
    println!("encrypt: #5");
    let secret_bn = BigInt::from_hex(&secret_hex);
    println!("encrypt: #6");
    let secret: Secp256k1Scalar = ECScalar::from(&secret_bn);

    println!("encrypt: #7");
    let G: GE = GE::generator();

    println!("encrypt: #8");
    let (witness, segments) =
        Msegmentation::to_encrypted_segments(&secret, &SEGMENT_SIZE, NUM_OF_SEGMENTS, &public_key, &G);

    println!("encrypt: #9");
    Ok(cx.string(serde_json::to_string(&(witness, segments)).unwrap()))
}

#[allow(non_snake_case)]
pub fn decrypt(mut cx: FunctionContext) -> JsResult<JsString> {
    let expected_args = 2;
    if cx.len() != expected_args {
        return cx.throw_error("Invalid number of arguments");
    }

    println!("decrypt: #1");
    let private_key_hex: String = cx.argument::<JsString>(0)?.value();  // decryption key
    println!("decrypt: #2");
    let private_key_bn = BigInt::from_hex(&private_key_hex);
    println!("decrypt: #3");
    let private_key: Secp256k1Scalar = ECScalar::from(&private_key_bn);

    println!("decrypt: #4");
    let DE_vec: Helgamalsegmented = serde_json::from_str(&cx.argument::<JsString>(1)?.value())
        .expect("failed deserialization Helgamalsegmented");

    println!("decrypt: #5");
    let G: GE = GE::generator();

    println!("decrypt: #6");
    let secret = Msegmentation::decrypt(&DE_vec, &G, &private_key, &SEGMENT_SIZE)
        .expect("failed decrypting");

    println!("decrypt: #7");
    Ok(cx.string(secret.to_big_int().to_hex()))
}

#[allow(non_snake_case)]
pub fn prove(mut cx: FunctionContext) -> JsResult<JsString> {
    let expected_args = 3;
    if cx.len() != expected_args {
        return cx.throw_error("Invalid number of arguments");
    }

    println!("prove: #1");
    let public_key_hex: String = cx.argument::<JsString>(0)?.value();
    println!("prove: #2");
    let public_key_bytes = hex::decode(&public_key_hex)
        .expect(&format!("failed hex::decode of public_key {}", &public_key_hex));
    println!("prove: #3");
    let public_key: GE = ECPoint::from_bytes(public_key_bytes.as_slice())
        .expect(&format!("failed deserialization of public_key {}", &public_key_hex));

    println!("prove: #4");
    let segments: Witness = serde_json::from_str(&cx.argument::<JsString>(1)?.value())
        .expect("failed deserialization Witness");

    println!("prove: #5");
    let encryptions: Helgamalsegmented = serde_json::from_str(&cx.argument::<JsString>(2)?.value())
        .expect("failed deserialization Helgamalsegmented");

    println!("prove: #6");
    let G: GE = GE::generator();

    println!("prove: #7");
    let proof = Proof::prove(&segments, &encryptions, &G, &public_key, &SEGMENT_SIZE);

    println!("prove: #8");
    Ok(cx.string(serde_json::to_string(&proof).unwrap()))
}

#[allow(non_snake_case)]
pub fn verify(mut cx: FunctionContext) -> JsResult<JsBoolean> {
    let expected_args = 4;
    if cx.len() != expected_args {
        return cx.throw_error("Invalid number of arguments");
    }

    println!("verify: #1");
    let proof: Proof = serde_json::from_str(&cx.argument::<JsString>(0)?.value())
        .expect("failed deserialization of Proof");

    println!("verify: #2");
    let encryption_key_hex: String = cx.argument::<JsString>(1)?.value();
    println!("verify: #3");
    let encryption_key_bytes = hex::decode(&encryption_key_hex)
        .expect(&format!("failed hex::decode of encryption_key {}", &encryption_key_hex));
    println!("verify: #4");
    let encryption_key: GE = ECPoint::from_bytes(encryption_key_bytes.as_slice())
        .expect(&format!("failed deserialization of encryption_key {}", &encryption_key_hex));

    println!("verify: #5");
    let public_key_hex: String = cx.argument::<JsString>(2)?.value();
    println!("verify: #6");
    let public_key_bytes = hex::decode(&public_key_hex)
        .expect(&format!("failed hex::decode of public_key {}", &public_key_hex));
    println!("verify: #7");
    let public_key: GE = ECPoint::from_bytes(public_key_bytes.as_slice())
        .expect(&format!("failed deserialization of public_key {}", &public_key_hex));

    println!("verify: #8");
    let encryptions: Helgamalsegmented = serde_json::from_str(&cx.argument::<JsString>(3)?.value())
        .expect("failed deserialization Helgamalsegmented");

    println!("verify: #9");
    let G: GE = GE::generator();

    println!("verify: #10");
    match proof.verify(&encryptions, &G, &encryption_key, &public_key, &SEGMENT_SIZE) {
        Ok(_) => Ok(cx.boolean(true)),
        Err(_) => Ok(cx.boolean(false))
    }
}
