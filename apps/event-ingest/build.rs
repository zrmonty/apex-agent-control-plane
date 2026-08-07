fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut config = prost_build::Config::new();
    config.protoc_executable(protoc_bin_vendored::protoc_bin_path()?);
    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        .build_transport(true)
        // tonic_prost::ProstCodec maps every decode failure to
        // Status::internal(error.to_string()), which both leaks prost's
        // internal field path and hands clients a code they widely treat as
        // retryable. See src/codec.rs.
        .codec_path("crate::RedactedProstCodec")
        .compile_with_config(
            config,
            &["../../contracts/proto/apex/v1/event.proto"],
            &["../../contracts/proto"],
        )?;
    println!("cargo:rerun-if-changed=../../contracts/proto/apex/v1/event.proto");
    Ok(())
}
