//! Fixed production entry point; no environment or RPC path selection.
fn main() -> std::process::ExitCode {
    let mut args = std::env::args_os().skip(1);
    let path = match (args.next(), args.next(), args.next()) {
        (Some(flag), Some(path), None)
            if flag == "--config-dir" && std::path::Path::new(&path).is_absolute() =>
        {
            path
        }
        _ => {
            eprintln!("RUNTIME_USAGE: --config-dir ABSOLUTE_PATH");
            return std::process::ExitCode::FAILURE;
        }
    };
    #[cfg(target_os = "linux")]
    let result = apex_proxy_runtime_agent::service::run(std::path::Path::new(&path));
    #[cfg(not(target_os = "linux"))]
    let result: Result<(), &'static str> = {
        drop(path);
        Err("RUNTIME_PRODUCTION_REQUIRES_LINUX")
    };
    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(code) => {
            eprintln!("{code}");
            std::process::ExitCode::FAILURE
        }
    }
}
