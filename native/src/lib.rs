#[macro_use]
extern crate neon;
extern crate centipede;
extern crate curv;
extern crate hex;

mod verifiable_encryption;
use crate::verifiable_encryption as ve;

mod gradual_release;
use crate::gradual_release as gr;

pub const SEGMENT_SIZE: usize = 8;
pub const NUM_OF_SEGMENTS: usize = 32;

register_module!(mut cx, {
    cx.export_function("ve_encrypt", ve::encrypt)?;
    cx.export_function("ve_decrypt", ve::decrypt)?;
    cx.export_function("ve_prove", ve::prove)?;
    cx.export_function("ve_verify", ve::verify)?;

    cx.export_function("gr_create_share", gr::create_share)?;
    cx.export_function("gr_verify_start", gr::verify_start)?;
    cx.export_function("gr_segment_k_proof", gr::segment_k_proof)?;
    cx.export_function("gr_verify_segment", gr::verify_segment)?;
    cx.export_function("gr_extract_secret", gr::extract_secret)?;

    Ok(())
});
