use lob_replay::canonical_output::scan_canonical_output;
use std::env;
use std::path::PathBuf;

fn main() {
    let mut args = env::args_os();
    let executable = PathBuf::from(args.next().unwrap_or_default());
    let Some(path) = args.next().map(PathBuf::from) else {
        eprintln!("usage: {} <canonical-output.bnpub>", executable.display());
        std::process::exit(2);
    };
    if args.next().is_some() {
        eprintln!("canonical-scan: too many arguments");
        std::process::exit(2);
    }
    match scan_canonical_output(&path).and_then(|scan| {
        serde_json::to_string_pretty(&scan)
            .map_err(|error| format!("serialize canonical scan: {error}"))
    }) {
        Ok(report) => println!("{report}"),
        Err(error) => {
            eprintln!("canonical-scan: {error}");
            std::process::exit(2);
        }
    }
}
