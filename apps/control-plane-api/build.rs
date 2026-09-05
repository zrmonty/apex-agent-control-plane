fn main() -> Result<(), Box<dyn std::error::Error>> {
    use prost::Message;
    let out = std::path::PathBuf::from(std::env::var("OUT_DIR")?);
    let descriptor_path = out.join("apex-management.binpb");
    let mut config = prost_build::Config::new();
    config.file_descriptor_set_path(&descriptor_path);
    config.enable_type_names();
    config.protoc_executable(protoc_bin_vendored::protoc_bin_path()?);
    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        .build_transport(true)
        // Shared static decoder failures; never expose malformed wire field paths.
        .codec_path("apex_contract::RedactedProstCodec")
        .compile_with_config(
            config,
            &[
                "../../contracts/proto/apex/v1/control.proto",
                "../../contracts/proto/apex/v1/governance.proto",
                "../../contracts/proto/apex/v1/mcp_proxy.proto",
                "../../contracts/proto/apex/v1/proxy_runtime.proto",
                "../../contracts/proto/apex/v1/proxy_runtime_authority.proto",
            ],
            &["../../contracts/proto"],
        )?;
    let bytes = std::fs::read(&descriptor_path)?;
    let descriptors = prost_types::FileDescriptorSet::decode(bytes.as_slice())?;
    // The legacy control stream uses prost_types::Struct and has no browser
    // bridge. Generate ProtoJSON only for the typed management boundaries.
    let names: Vec<String> = descriptors
        .file
        .iter()
        .filter(|file| {
            file.package.as_deref() == Some("apex.v1")
                && !file
                    .name
                    .as_deref()
                    .unwrap_or_default()
                    .ends_with("/control.proto")
        })
        .flat_map(|file| {
            file.message_type
                .iter()
                .filter_map(|message| message.name.as_ref())
                .chain(
                    file.enum_type
                        .iter()
                        .filter_map(|value| value.name.as_ref()),
                )
                .map(|name| format!(".apex.v1.{name}"))
        })
        .collect();
    pbjson_build::Builder::new()
        .register_descriptors(&bytes)?
        .build(&names)?;
    println!("cargo:rerun-if-changed=../../contracts/proto/apex/v1");
    println!("cargo:rerun-if-changed=../../contracts/proto/apex/v1/control.proto");
    println!("cargo:rerun-if-changed=../../contracts/proto/apex/v1/governance.proto");
    println!("cargo:rerun-if-changed=../../contracts/proto/apex/v1/mcp_proxy.proto");
    Ok(())
}
