//! `pool-runner` binary.
//!
//!   pool-runner run      one job: request + input on stdin, response + output on stdout (see `ipc`)
//!   pool-runner probe    sandbox self-test (tests only): --connect ADDR --dns HOST --read FILE --write-dir DIR --spawn
//!   pool-runner version
//!
//! It is always started by `pool-core` inside the OS sandbox; it never opens a network connection, never
//! writes a file and accepts only canonical input for a model whose signed manifest verifies.

fn main() {
    // the embedded build info the release marker check looks for
    std::hint::black_box(pool_proto::BUILD_INFO);
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("run") => {
            let mut stdin = std::io::stdin().lock();
            let mut stdout = std::io::stdout().lock();
            match pool_runner::serve(&mut stdin, &mut stdout) {
                Ok(true) => std::process::exit(0),
                Ok(false) => std::process::exit(3),
                Err(_) => std::process::exit(4),
            }
        }
        Some("probe") => {
            let rep = pool_runner::probe::run(&pool_runner::probe::ProbeArgs::parse(&args[1..]));
            println!("{}", serde_json::to_string(&rep).unwrap_or_default());
        }
        Some("version") | Some("--version") => {
            println!("pool-runner {} (protocol {}; {})", env!("CARGO_PKG_VERSION"), pool_proto::PROTOCOL_VERSION, pool_proto::BUILD_INFO);
        }
        _ => {
            eprintln!("usage: pool-runner run|probe|version");
            std::process::exit(2);
        }
    }
}
