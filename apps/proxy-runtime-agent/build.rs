fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out = std::path::PathBuf::from(std::env::var("OUT_DIR")?);
    let descriptor = out.join("apex-runtime-agent.binpb");
    let mut config = prost_build::Config::new();
    config.file_descriptor_set_path(&descriptor);
    config.enable_type_names();
    config.protoc_executable(protoc_bin_vendored::protoc_bin_path()?);
    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        .build_transport(true)
        .codec_path("apex_contract::RedactedProstCodec")
        .compile_with_config(
            config,
            &["../../contracts/proto/apex/v1/proxy_runtime.proto"],
            &["../../contracts/proto"],
        )?;
    pbjson_build::Builder::new()
        .register_descriptors(&std::fs::read(descriptor)?)?
        .build(&[".apex.v1"])?;
    for file in [
        "proxy_runtime.proto",
        "mcp_proxy.proto",
        "proxy_management.proto",
        "proxy_trace.proto",
        "proxy_approval.proto",
    ] {
        println!("cargo:rerun-if-changed=../../contracts/proto/apex/v1/{file}");
    }
    println!("cargo:rerun-if-changed=build.rs");
    Ok(())
}
