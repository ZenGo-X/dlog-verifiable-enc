#[macro_use]
extern crate neon;
extern crate centipede;
extern crate curv;
extern crate hex;

mod ve;

register_module!(mut cx, {
    cx.export_function("ve_encrypt", ve::encrypt)?;
    cx.export_function("ve_decrypt", ve::decrypt)?;
    cx.export_function("ve_prove", ve::prove)?;
    cx.export_function("ve_verify", ve::verify)?;

    Ok(())
});
