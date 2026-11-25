fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Use a pinned protoc so builds do not depend on the host.
    let protoc = protoc_bin_vendored::protoc_bin_path()?;
    // SAFETY: set before any other thread is spawned in this build script.
    unsafe { std::env::set_var("PROTOC", protoc) };
    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        .skip_debug(["torngat.control.v1.VolumeKeyResponse"])
        .compile_protos(&["proto/control.proto", "proto/storage.proto"], &["proto"])?;
    println!("cargo:rerun-if-changed=proto");
    Ok(())
}
