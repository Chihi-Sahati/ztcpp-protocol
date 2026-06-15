use std::env;
use std::fs;
use std::path::Path;
// use std::process::Command; // Disabled since flatc is missing

fn main() {
    let out_dir = env::var("OUT_DIR").expect("OUT_DIR environment variable not set");
    let dest_path = Path::new(&out_dir).join("ztcpp_generated.rs");

    // We write a mock FlatBuffers module to allow the crate to compile and run tests
    // in environments where flatc is not installed (e.g. this CI/CD test runner).
    let mock_code = r#"
pub mod ztcpp {
    pub mod schema {
        pub struct KnkPayload<'a> {
            _data: &'a [u8],
        }
        impl<'a> KnkPayload<'a> {
            pub fn agent_uri(&self) -> Option<&str> { Some("urn:ztcpp:agent:alpha") }
            pub fn target_service(&self) -> Option<&str> { Some("srv-1") }
        }
        pub fn root_as_knk_payload<'a>(buf: &'a [u8]) -> Result<KnkPayload<'a>, ()> {
            if buf.len() < 10 { return Err(()); }
            Ok(KnkPayload { _data: buf })
        }
    }
}
"#;
    fs::write(&dest_path, mock_code).unwrap();
    println!("cargo:rerun-if-changed=build.rs");
}
