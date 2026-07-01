pub mod crypto_pipeline;

#[allow(dead_code, unused_imports, clippy::all)]
pub mod nhp_sba_schema {
    include!(concat!(env!("OUT_DIR"), "/nhp_sba_generated.rs"));
}
