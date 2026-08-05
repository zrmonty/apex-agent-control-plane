fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut config = prost_build::Config::new();
    config.protoc_executable(protoc_bin_vendored::protoc_bin_path()?);
    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        .build_transport(true)
        .compile_with_config(
            config,
            &["../../contracts/proto/apex/v1/event.proto"],
            &["../../contracts/proto"],
        )?;
    println!("cargo:rerun-if-changed=../../contracts/proto/apex/v1/event.proto");
    Ok(())
}
