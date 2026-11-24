//! `pool-runner` binary.
//!
//!   pool-runner run      one job: request + input on stdin, response + output on stdout (see `ipc`)
//!   pool-runner probe    sandbox self-test (tests only): --connect ADDR --dns HOST --read FILE --write-dir DIR --spawn
//!   pool-runner version
//!   pool-runner capabilities   JSON: what this build can do (`{"metal": bool}`); the agent grants the macOS GPU
//!                              sandbox rules only to a runner that reports Metal
//!
//! It is always started by `pool-core` inside the OS sandbox; it never opens a network connection, never
//! writes a file and accepts only canonical input for a model whose signed manifest verifies.

/// End the one-job process right after the response is out. On macOS and Linux `std::process::exit` runs the C++
/// static destructors of a loaded ONNX Runtime while its thread pool still exists, and libc++ aborts ("mutex lock
/// failed"): the job's answer was already sent, but every job would end in a crash (and a crash report). `_exit`
/// skips those destructors; stdout and stderr are flushed first, and the process holds nothing else to save.
fn exit_now(code: i32) -> ! {
    use std::io::Write;
    let _ = std::io::stdout().flush();
    let _ = std::io::stderr().flush();
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    // SAFETY: `_exit` only ends the process; nothing is left to run or flush in this one-job process.
    unsafe {
        libc::_exit(code)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    std::process::exit(code)
}

fn main() {
    // the embedded build info the release marker check looks for
    std::hint::black_box(pool_proto::BUILD_INFO);
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("run") => {
            let mut stdin = std::io::stdin().lock();
            let mut stdout = std::io::stdout().lock();
            let code = match pool_runner::serve(&mut stdin, &mut stdout) {
                Ok(true) => 0,
                Ok(false) => 3,
                Err(_) => 4,
            };
            drop(stdout);
            exit_now(code);
        }
        Some("probe") => {
            let rep = pool_runner::probe::run(&pool_runner::probe::ProbeArgs::parse(&args[1..]));
            println!("{}", serde_json::to_string(&rep).unwrap_or_default());
        }
        Some("capabilities") => {
            println!("{}", serde_json::json!({ "metal": pool_runner::accel::METAL_BUILD }));
        }
        Some("version") | Some("--version") => {
            println!("pool-runner {} (protocol {}; {})", env!("CARGO_PKG_VERSION"), pool_proto::PROTOCOL_VERSION, pool_proto::BUILD_INFO);
        }
        _ => {
            eprintln!("usage: pool-runner run|probe|version|capabilities");
            std::process::exit(2);
        }
    }
}
