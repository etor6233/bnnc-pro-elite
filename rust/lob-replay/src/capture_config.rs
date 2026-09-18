//! Exact public market-data capture configuration.
//!
//! The collector still compiles fixed endpoints so a mutable file cannot
//! redirect traffic.  This parser proves that the hash-bound configuration
//! describes those exact effective constants; unknown fields or drift fail
//! before a socket or artifact is created.

use crate::Result;
use serde::Deserialize;
use std::fs;
use std::path::Path;

pub const PUBLIC_WS_BASE: &str = "wss://data-stream.binance.vision:443";
pub const PUBLIC_REST_BASE: &str = "https://data-api.binance.vision";
pub const PUBLIC_SPEC_REVISION: &str = "976cc580553890e92031b77306147c0ed1de5a46";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct JsonConfigV1 {
    websocket_base: String,
    rest_base: String,
    depth_interval: String,
    time_unit: String,
    streams: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicMarketDataConfigV1 {
    schema_version: String,
    environment: String,
    venue: String,
    symbols: Vec<String>,
    json: JsonConfigV1,
    credentials: String,
    order_entry: String,
    spec_revision: String,
}

pub fn validate_public_capture_config(path: &Path) -> Result<()> {
    let bytes = fs::read(path)
        .map_err(|error| format!("read public capture config {}: {error}", path.display()))?;
    let config: PublicMarketDataConfigV1 = serde_json::from_slice(&bytes)
        .map_err(|error| format!("parse public capture config {}: {error}", path.display()))?;
    if config.schema_version != "1"
        || config.environment != "production-public-market-data"
        || config.venue != "binance-spot"
        || config.symbols != ["BTCUSDT", "ETHUSDT"]
        || config.json.websocket_base != PUBLIC_WS_BASE
        || config.json.rest_base != PUBLIC_REST_BASE
        || config.json.depth_interval != "100ms"
        || config.json.time_unit != "MICROSECOND"
        || config.json.streams != ["depth", "trade"]
        || config.credentials != "FORBIDDEN"
        || config.order_entry != "ABSENT"
        || config.spec_revision != PUBLIC_SPEC_REVISION
    {
        return Err(
            "public capture config differs from the compiled effective contract".to_owned(),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::validate_public_capture_config;
    use tempfile::tempdir;

    const VALID: &str = r#"{
      "schema_version":"1",
      "environment":"production-public-market-data",
      "venue":"binance-spot",
      "symbols":["BTCUSDT","ETHUSDT"],
      "json":{
        "websocket_base":"wss://data-stream.binance.vision:443",
        "rest_base":"https://data-api.binance.vision",
        "depth_interval":"100ms",
        "time_unit":"MICROSECOND",
        "streams":["depth","trade"]
      },
      "credentials":"FORBIDDEN",
      "order_entry":"ABSENT",
      "spec_revision":"976cc580553890e92031b77306147c0ed1de5a46"
    }"#;

    #[test]
    fn exact_public_config_is_accepted_and_drift_is_rejected() {
        let directory = tempdir().unwrap();
        let valid = directory.path().join("valid.json");
        std::fs::write(&valid, VALID).unwrap();
        validate_public_capture_config(&valid).unwrap();

        let drifted = directory.path().join("drifted.json");
        std::fs::write(&drifted, VALID.replace("trade", "aggTrade")).unwrap();
        assert!(validate_public_capture_config(&drifted).is_err());

        let unknown = directory.path().join("unknown.json");
        std::fs::write(&unknown, VALID.replacen('{', "{\"extra\":true,", 1)).unwrap();
        assert!(validate_public_capture_config(&unknown).is_err());
    }
}
