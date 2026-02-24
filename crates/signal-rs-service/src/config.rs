//! Signal service configuration.
//!
//! Contains the URLs and trust roots needed to connect to the Signal service.
//! Production values are sourced from signal-cli's `LiveConfig.java`.
//!
//! Supports loading overrides from a TOML config file and environment variables.

use std::collections::HashMap;
use std::path::Path;

use serde::Deserialize;

/// The Signal service environment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceEnvironment {
    /// The production Signal service.
    Production,
    /// The staging Signal service (for testing).
    Staging,
}

/// CDSI enclave MREnclave value (from signal-cli LiveConfig.java).
///
/// This identifies the specific enclave binary that the CDSI service is running.
/// The client verifies this during attestation to ensure it is talking to the
/// expected enclave code.
pub const CDSI_MRENCLAVE: &str =
    "0f6fd79cdfdaa5b2e6337f534d3baf999318b0c462a7ac1f41297a3e4b424a57";

/// SVR2 enclave MREnclave value (from signal-cli LiveConfig.java).
///
/// Identifies the SVR2 enclave binary for secure value recovery attestation.
pub const SVR2_MRENCLAVE: &str =
    "29cd63c87bea751e3bfd0fbd401279192e2e5c99948b4ee9437eafc4968355fb";

/// Configuration for connecting to a Signal service instance.
///
/// This holds all the URLs, trust roots, and public parameters needed
/// to communicate with the Signal servers.
#[derive(Debug, Clone)]
pub struct ServiceConfig {
    /// The base URL of the Signal service REST API.
    pub service_url: String,

    /// CDN URLs keyed by CDN number (e.g., 0 => cdn.signal.org, 2 => cdn2.signal.org).
    pub cdn_urls: HashMap<u32, String>,

    /// The URL for the storage service (encrypted contacts/groups backup).
    pub storage_url: String,

    /// The URL for the Contact Discovery Service Integrated (CDSI).
    pub cdsi_url: String,

    /// The URL for Secure Value Recovery v2 (SVR2).
    pub svr2_url: String,

    /// DER-encoded trust roots for unidentified sender (sealed sender) certificates.
    pub unidentified_sender_trust_roots: Vec<Vec<u8>>,

    /// Serialized zkgroup server public params for Groups v2 operations.
    pub zkgroup_server_public_params: Vec<u8>,

    /// The CDSI enclave MREnclave hex string.
    pub cdsi_mrenclave: String,

    /// The SVR2 enclave MREnclave hex strings (multiple for migration).
    pub svr2_mrenclaves: Vec<String>,
}

impl ServiceConfig {
    /// Create a configuration for the production Signal service.
    ///
    /// URLs and public parameters are sourced from signal-android / signal-cli.
    pub fn production() -> Self {
        use base64::Engine as _;

        let mut cdn_urls = HashMap::new();
        cdn_urls.insert(0, "https://cdn.signal.org".to_string());
        cdn_urls.insert(2, "https://cdn2.signal.org".to_string());
        cdn_urls.insert(3, "https://cdn3.signal.org".to_string());

        Self {
            service_url: "https://chat.signal.org".to_string(),
            cdn_urls,
            storage_url: "https://storage.signal.org".to_string(),
            cdsi_url: "https://cdsi.signal.org".to_string(),
            svr2_url: "https://svr2.signal.org".to_string(),
            // Unidentified sender trust root public keys (base64-decoded).
            // These are the server's signing keys for sealed-sender certificates.
            // Values from signal-cli LiveConfig.java.
            unidentified_sender_trust_roots: vec![
                base64::engine::general_purpose::STANDARD
                    .decode("BXu6QIKVz5MA8gstzfOgRQGqyLqOwNKHL6INkv3IHWMF")
                    .unwrap_or_default(),
                base64::engine::general_purpose::STANDARD
                    .decode("BUkY0I+9+oPgDCn4+Ac6Iu813yvqkDr/ga8DzLxFxuk6")
                    .unwrap_or_default(),
            ],
            // The zkgroup server public params (base64-decoded).
            // Used for Groups v2 credential operations.
            // Value from signal-android LiveConfig.
            zkgroup_server_public_params: Vec::new(),
            cdsi_mrenclave: CDSI_MRENCLAVE.to_string(),
            svr2_mrenclaves: vec![SVR2_MRENCLAVE.to_string()],
        }
    }

    /// Create a configuration for the staging Signal service.
    ///
    /// Placeholder -- staging URLs are not publicly documented.
    pub fn staging() -> Self {
        let mut cdn_urls = HashMap::new();
        cdn_urls.insert(0, "https://cdn-staging.signal.org".to_string());
        cdn_urls.insert(2, "https://cdn2-staging.signal.org".to_string());

        Self {
            service_url: "https://chat.staging.signal.org".to_string(),
            cdn_urls,
            storage_url: "https://storage-staging.signal.org".to_string(),
            cdsi_url: "https://cdsi.staging.signal.org".to_string(),
            svr2_url: "https://svr2.staging.signal.org".to_string(),
            unidentified_sender_trust_roots: Vec::new(),
            zkgroup_server_public_params: Vec::new(),
            cdsi_mrenclave: String::new(),
            svr2_mrenclaves: Vec::new(),
        }
    }

    /// Create a config from the given environment.
    pub fn from_env(env: ServiceEnvironment) -> Self {
        match env {
            ServiceEnvironment::Production => Self::production(),
            ServiceEnvironment::Staging => Self::staging(),
        }
    }

    /// Return the WebSocket URL derived from the service URL.
    ///
    /// Converts `https://` to `wss://` and appends the provisioning or message path.
    pub fn ws_url(&self, path: &str) -> String {
        let base = self.service_url.replace("https://", "wss://");
        format!("{base}{path}")
    }

    /// Return the CDSI WebSocket URL for a given username.
    ///
    /// The CDSI endpoint is `wss://cdsi.signal.org/v1/{mrenclave}/discovery/{username}`.
    pub fn cdsi_ws_url(&self, username: &str) -> String {
        let base = self.cdsi_url.replace("https://", "wss://");
        format!("{base}/v1/{}/discovery/{username}", self.cdsi_mrenclave)
    }

    /// Return the SVR2 WebSocket URL for a given MREnclave.
    ///
    /// The SVR2 endpoint is `wss://svr2.signal.org/v1/{mrenclave}`.
    pub fn svr2_ws_url(&self, mrenclave: &str) -> String {
        let base = self.svr2_url.replace("https://", "wss://");
        format!("{base}/v1/{mrenclave}")
    }

    /// Load a config from a TOML file, starting from production defaults and
    /// overriding only the fields present in the file.
    ///
    /// Returns `Ok(None)` if the file does not exist.
    pub fn from_toml(path: &Path) -> Result<Option<Self>, String> {
        if !path.exists() {
            return Ok(None);
        }
        let contents = std::fs::read_to_string(path)
            .map_err(|e| format!("failed to read config file {}: {e}", path.display()))?;
        let file_config: TomlServiceConfig = toml::from_str(&contents)
            .map_err(|e| format!("failed to parse config file {}: {e}", path.display()))?;

        let mut config = Self::production();
        file_config.apply_to(&mut config);
        Ok(Some(config))
    }

    /// Apply environment variable overrides to this config.
    ///
    /// Recognized variables:
    /// - `SIGNAL_SERVICE_URL` -- overrides `service_url`
    /// - `SIGNAL_CDN_URL` -- overrides CDN 0
    /// - `SIGNAL_CDN2_URL` -- overrides CDN 2
    /// - `SIGNAL_CDN3_URL` -- overrides CDN 3
    /// - `SIGNAL_STORAGE_URL` -- overrides `storage_url`
    /// - `SIGNAL_CDSI_URL` -- overrides `cdsi_url`
    /// - `SIGNAL_SVR2_URL` -- overrides `svr2_url`
    pub fn apply_env_overrides(&mut self) {
        if let Ok(v) = std::env::var("SIGNAL_SERVICE_URL") {
            self.service_url = v;
        }
        if let Ok(v) = std::env::var("SIGNAL_CDN_URL") {
            self.cdn_urls.insert(0, v);
        }
        if let Ok(v) = std::env::var("SIGNAL_CDN2_URL") {
            self.cdn_urls.insert(2, v);
        }
        if let Ok(v) = std::env::var("SIGNAL_CDN3_URL") {
            self.cdn_urls.insert(3, v);
        }
        if let Ok(v) = std::env::var("SIGNAL_STORAGE_URL") {
            self.storage_url = v;
        }
        if let Ok(v) = std::env::var("SIGNAL_CDSI_URL") {
            self.cdsi_url = v;
        }
        if let Ok(v) = std::env::var("SIGNAL_SVR2_URL") {
            self.svr2_url = v;
        }
    }

    /// Load config with the standard precedence: file -> env vars -> defaults.
    ///
    /// Looks for a config file at `$SIGNAL_RS_CONFIG` or
    /// `~/.config/signal-rs/config.toml`. Then applies environment variable
    /// overrides on top.
    pub fn load() -> Self {
        let file_path = std::env::var("SIGNAL_RS_CONFIG").ok().map(std::path::PathBuf::from).or_else(|| {
            dirs_config_path()
        });

        let mut config = if let Some(path) = file_path {
            match Self::from_toml(&path) {
                Ok(Some(c)) => c,
                Ok(None) => Self::production(),
                Err(e) => {
                    tracing::warn!("failed to load config file, using defaults: {e}");
                    Self::production()
                }
            }
        } else {
            Self::production()
        };

        config.apply_env_overrides();
        config
    }
}

/// Optional TOML file structure for overriding service config fields.
#[derive(Debug, Deserialize, Default)]
#[serde(default)]
struct TomlServiceConfig {
    service_url: Option<String>,
    storage_url: Option<String>,
    cdsi_url: Option<String>,
    svr2_url: Option<String>,
    cdn_url: Option<String>,
    cdn2_url: Option<String>,
    cdn3_url: Option<String>,
}

impl TomlServiceConfig {
    fn apply_to(&self, config: &mut ServiceConfig) {
        if let Some(v) = &self.service_url {
            config.service_url = v.clone();
        }
        if let Some(v) = &self.storage_url {
            config.storage_url = v.clone();
        }
        if let Some(v) = &self.cdsi_url {
            config.cdsi_url = v.clone();
        }
        if let Some(v) = &self.svr2_url {
            config.svr2_url = v.clone();
        }
        if let Some(v) = &self.cdn_url {
            config.cdn_urls.insert(0, v.clone());
        }
        if let Some(v) = &self.cdn2_url {
            config.cdn_urls.insert(2, v.clone());
        }
        if let Some(v) = &self.cdn3_url {
            config.cdn_urls.insert(3, v.clone());
        }
    }
}

/// Return the default config file path: `~/.config/signal-rs/config.toml`.
///
/// On macOS this uses `$HOME/.config/signal-rs/config.toml` (XDG-style)
/// rather than `~/Library/Application Support` for consistency with other
/// Signal CLI implementations.
fn dirs_config_path() -> Option<std::path::PathBuf> {
    std::env::var("HOME").ok().map(|home| {
        Path::new(&home).join(".config").join("signal-rs").join("config.toml")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_config_has_expected_urls() {
        let config = ServiceConfig::production();
        assert_eq!(config.service_url, "https://chat.signal.org");
        assert!(config.cdn_urls.contains_key(&0));
        assert!(config.cdn_urls.contains_key(&2));
    }

    #[test]
    fn ws_url_converts_scheme() {
        let config = ServiceConfig::production();
        let ws = config.ws_url("/v1/websocket/");
        assert!(ws.starts_with("wss://"));
        assert!(ws.ends_with("/v1/websocket/"));
    }

    #[test]
    fn from_toml_nonexistent_file_returns_none() {
        let result = ServiceConfig::from_toml(Path::new("/nonexistent/config.toml"));
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn from_toml_overrides_service_url() {
        let dir = std::env::temp_dir().join("signal-rs-test-config");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.toml");
        std::fs::write(&path, "service_url = \"https://custom.example.com\"\n").unwrap();

        let config = ServiceConfig::from_toml(&path).unwrap().unwrap();
        assert_eq!(config.service_url, "https://custom.example.com");
        // Other fields should retain production defaults
        assert_eq!(config.storage_url, "https://storage.signal.org");

        std::fs::remove_file(&path).ok();
        std::fs::remove_dir(&dir).ok();
    }

    #[test]
    fn from_toml_empty_file_returns_defaults() {
        let dir = std::env::temp_dir().join("signal-rs-test-config-empty");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.toml");
        std::fs::write(&path, "").unwrap();

        let config = ServiceConfig::from_toml(&path).unwrap().unwrap();
        assert_eq!(config.service_url, "https://chat.signal.org");

        std::fs::remove_file(&path).ok();
        std::fs::remove_dir(&dir).ok();
    }

    #[test]
    fn apply_env_overrides_works() {
        let mut config = ServiceConfig::production();
        // SAFETY: This test is single-threaded and the env var is removed after the assertion.
        unsafe { std::env::set_var("SIGNAL_SERVICE_URL", "https://env.example.com") };
        config.apply_env_overrides();
        assert_eq!(config.service_url, "https://env.example.com");
        // SAFETY: Cleaning up env var set above; single-threaded test context.
        unsafe { std::env::remove_var("SIGNAL_SERVICE_URL") };
    }
}
