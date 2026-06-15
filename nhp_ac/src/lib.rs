pub mod crypto_pipeline;

#[allow(dead_code, unused_imports, clippy::all)]
pub mod ztcpp_schema {
    include!(concat!(env!("OUT_DIR"), "/ztcpp_generated.rs"));
}
