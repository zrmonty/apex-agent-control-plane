/// Compiles `contracts/proto/apex/v1/control.proto` for this crate's own,
/// independent gRPC client. Deliberately its own `build.rs`/codegen pass
/// rather than a path dependency on `apex-control-plane-api` for its
/// already-generated `proto` module: this binary holds the one credential in
/// the whole system that a compromised agent must never be able to read (see
/// `src/lib.rs`), and pulling in the control-plane-api server crate -- with
/// its Keycloak/JWKS client, Postgres driver, and file-outbox machinery, none
/// of which this binary uses -- would grow this process's dependency tree for
/// no benefit to the property it exists to hold. `tonic-prost-build` still
/// generates a server stub from the same `.proto` file; this crate simply
/// never implements or serves it.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut config = prost_build::Config::new();
    config.protoc_executable(protoc_bin_vendored::protoc_bin_path()?);
    tonic_prost_build::configure()
        .build_server(false)
        .build_client(true)
        .build_transport(true)
        .compile_with_config(
            config,
            &["../../contracts/proto/apex/v1/control.proto"],
            &["../../contracts/proto"],
        )?;
    println!("cargo:rerun-if-changed=../../contracts/proto/apex/v1/control.proto");
    Ok(())
}
