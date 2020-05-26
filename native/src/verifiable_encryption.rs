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

    let public_key_hex: String = cx.argument::<JsString>(0)?.value();
    let public_key_bytes = hex::decode(&public_key_hex)
        .expect(&format!("failed hex::decode of public_key {}", &public_key_hex));
    let public_key: GE = ECPoint::from_bytes(public_key_bytes.as_slice())
        .expect(&format!("failed deserialization of public_key {}", &public_key_hex));

    let secret_hex: String = cx.argument::<JsString>(1)?.value();
    let secret_bn = BigInt::from_hex(&secret_hex);
    let secret: Secp256k1Scalar = ECScalar::from(&secret_bn);

    let G: GE = GE::generator();

    let (witness, segments) =
        Msegmentation::to_encrypted_segments(&secret, &SEGMENT_SIZE, NUM_OF_SEGMENTS, &public_key, &G);

    Ok(cx.string(serde_json::to_string(&(witness, segments)).unwrap()))
}

#[allow(non_snake_case)]
pub fn decrypt(mut cx: FunctionContext) -> JsResult<JsString> {
    let expected_args = 2;
    if cx.len() != expected_args {
        return cx.throw_error("Invalid number of arguments");
    }

    let private_key_hex: String = cx.argument::<JsString>(0)?.value();  // decryption key
    let private_key_bn = BigInt::from_hex(&private_key_hex);
    let private_key: Secp256k1Scalar = ECScalar::from(&private_key_bn);

    let DE_vec: Helgamalsegmented = serde_json::from_str(&cx.argument::<JsString>(1)?.value())
        .expect("failed deserialization Helgamalsegmented");

    let G: GE = GE::generator();

    let secret = Msegmentation::decrypt(&DE_vec, &G, &private_key, &SEGMENT_SIZE)
        .expect("failed decrypting");

    Ok(cx.string(secret.to_big_int().to_hex()))
}

#[allow(non_snake_case)]
pub fn prove(mut cx: FunctionContext) -> JsResult<JsString> {
    let expected_args = 3;
    if cx.len() != expected_args {
        return cx.throw_error("Invalid number of arguments");
    }

    let public_key_hex: String = cx.argument::<JsString>(0)?.value();
    let public_key_bytes = hex::decode(&public_key_hex)
        .expect(&format!("failed hex::decode of public_key {}", &public_key_hex));
    let public_key: GE = ECPoint::from_bytes(public_key_bytes.as_slice())
        .expect(&format!("failed deserialization of public_key {}", &public_key_hex));

    let segments: Witness = serde_json::from_str(&cx.argument::<JsString>(1)?.value())
        .expect("failed deserialization Witness");

    let encryptions: Helgamalsegmented = serde_json::from_str(&cx.argument::<JsString>(2)?.value())
        .expect("failed deserialization Helgamalsegmented");

    let G: GE = GE::generator();

    let proof = Proof::prove(&segments, &encryptions, &G, &public_key, &SEGMENT_SIZE);

    Ok(cx.string(serde_json::to_string(&proof).unwrap()))
}

#[allow(non_snake_case)]
pub fn verify(mut cx: FunctionContext) -> JsResult<JsBoolean> {
    let expected_args = 4;
    if cx.len() != expected_args {
        return cx.throw_error("Invalid number of arguments");
    }

    let proof: Proof = serde_json::from_str(&cx.argument::<JsString>(0)?.value())
        .expect("failed deserialization of Proof");

    let encryption_key_hex: String = cx.argument::<JsString>(1)?.value();
    let encryption_key_bytes = hex::decode(&encryption_key_hex)
        .expect(&format!("failed hex::decode of encryption_key {}", &encryption_key_hex));
    let encryption_key: GE = ECPoint::from_bytes(encryption_key_bytes.as_slice())
        .expect(&format!("failed deserialization of encryption_key {}", &encryption_key_hex));

    let public_key_hex: String = cx.argument::<JsString>(2)?.value();
    let public_key_bytes = hex::decode(&public_key_hex)
        .expect(&format!("failed hex::decode of public_key {}", &public_key_hex));
    let public_key: GE = ECPoint::from_bytes(public_key_bytes.as_slice())
        .expect(&format!("failed deserialization of public_key {}", &public_key_hex));

    let encryptions: Helgamalsegmented = serde_json::from_str(&cx.argument::<JsString>(3)?.value())
        .expect("failed deserialization Helgamalsegmented");

    let G: GE = GE::generator();

    match proof.verify(&encryptions, &G, &encryption_key, &public_key, &SEGMENT_SIZE) {
        Ok(_) => Ok(cx.boolean(true)),
        Err(_) => Ok(cx.boolean(false))
    }
}
