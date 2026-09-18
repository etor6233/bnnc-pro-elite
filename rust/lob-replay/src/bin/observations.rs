use lob_replay::observations::{materialize_depth_observations, materialize_trade_observations};
use std::env;
use std::path::PathBuf;

fn run() -> Result<(), String> {
    let mut args = env::args_os();
    let executable = PathBuf::from(args.next().unwrap_or_default());
    let kind = args
        .next()
        .and_then(|value| value.into_string().ok())
        .ok_or_else(|| {
            format!(
                "usage: {} depth <snapshot.bnraw> <depth.bnraw> | trade <trade.bnraw>",
                executable.display()
            )
        })?;
    let result = match kind.as_str() {
        "depth" => {
            let snapshot = args
                .next()
                .map(PathBuf::from)
                .ok_or_else(|| "depth requires snapshot path".to_owned())?;
            let raw = args
                .next()
                .map(PathBuf::from)
                .ok_or_else(|| "depth requires raw path".to_owned())?;
            if args.next().is_some() {
                return Err("too many depth arguments".to_owned());
            }
            materialize_depth_observations(&snapshot, &raw)?
        }
        "trade" => {
            let raw = args
                .next()
                .map(PathBuf::from)
                .ok_or_else(|| "trade requires raw path".to_owned())?;
            if args.next().is_some() {
                return Err("too many trade arguments".to_owned());
            }
            materialize_trade_observations(&raw)?
        }
        _ => return Err("kind must be depth or trade".to_owned()),
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&result)
            .map_err(|error| format!("serialize observations: {error}"))?
    );
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("observations: {error}");
        std::process::exit(2);
    }
}
