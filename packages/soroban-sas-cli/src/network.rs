#![allow(dead_code)]
//! Named-network resolution for the global `--network` option (issue #174).
//!
//! Wires `--network <name>` to a concrete RPC URL and network passphrase so
//! the flag actually changes command behavior instead of being accepted and
//! silently ignored. Precedence, applied uniformly by every subcommand via
//! [`crate::resolve_rpc_url`] / [`crate::resolve_network_passphrase`]:
//!
//! 1. An explicit subcommand flag (`--rpc-url`, `--network-passphrase`).
//! 2. The matching environment variable (`SOROBAN_RPC_URL`,
//!    `SOROBAN_NETWORK_PASSPHRASE`) — clap fills the subcommand flag from
//!    these automatically when the flag itself is absent.
//! 3. The global `--network <name>` shorthand, resolved by this module.
//! 4. Otherwise: a clear error naming what's missing.
//!
//! Additionally, a TOML configuration file can provide defaults for the
//! RPC URL and network passphrase, as well as a default network name.
//! See [`TomlConfig`] for the configuration schema.
//!
//! For unit tests, [`MockNetworkClient`] provides an in-memory implementation
//! of the network client trait so command logic can be exercised without
//! touching a live RPC endpoint.
use serde::Deserialize;

/// Resolved connection details for a named network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkConfig {
    pub rpc_url: String,
    pub network_passphrase: String,
}

/// TOML configuration file structure for default RPC/network settings.
///
/// Example `config.toml`:
/// ```toml
/// default_network = "testnet"
/// rpc_url = "https://soroban-testnet.stellar.org"
/// network_passphrase = "Test SDF Network ;; September 2015"
/// ```
#[derive(Debug, Clone, Default, Deserialize)]
#[allow(dead_code)]
pub struct TomlConfig {
    /// Optional default network name (e.g. "testnet", "futurenet", "mainnet", "local").
    pub default_network: Option<String>,
    /// Optional default R PC URL.
    pub rpc_url: Option<String>,
    /// Optional default network passphrase.
    pub network_passphrase: Option<String>,
}

/// Resolves a `--network` shorthand to its RPC URL and passphrase.
///
/// Recognized names: `testnet`, `futurenet`, `mainnet` (alias `pubnet`), and
/// `local` (alias `standalone`, for `stellar-core`/`soroban-rpc` run via the
/// quickstart image). Matching is case-insensitive.
pub fn resolve_network(name: &str) -> Result<NetworkConfig, String> {
    let config = match name.to_ascii_lowercase().as_str() {
        "testnet" => NetworkConfig {
            rpc_url: "https://soroban-testnet.stellar.org".to_string(),
            network_passphrase: "Test SDF Network ; September 2015".to_string(),
        },
        "futurenet" => NetworkConfig {
            rpc_url: "https://rpc-futurenet.stellar.org".to_string(),
            network_passphrase: "Test SDF Future Network ; October 2022".to_string(),
        },
        "mainnet" | "pubnet" => NetworkConfig {
            rpc_url: "https://mainnet.sorobanrpc.com".to_string(),
            network_passphrase: "Public Global Stellar Network ; September 2015".to_string(),
        },
        "local" | "standalone" => NetworkConfig {
            rpc_url: "http://localhost:8000/soroban/rpc".to_string(),
            network_passphrase: "Standalone Network ; February 2017".to_string(),
        },
        other => {
            return Err(format!(
                "unknown --network {other:?}: expected one of \
                 testnet, futurenet, mainnet (or pubnet), local (or standalone)"
            ))
        }
    };
    Ok(config)
}

/// Minimal network client abstraction used by the CLI when talking to an RPC
/// endpoint. Kept intentionally small so it can be mocked in unit tests.
pub trait NetworkClient {
    /// Returns the RPC URL this client is configured to talk to.
    fn rpc_url(&self) -> &str;

    /// Returns the network passphrase this client is configured for.
    fn network_passphrase(&self) -> &str;
}

/// In-memory [`NetworkClient`] for unit testing.
///
/// Construct one from a [`NetworkConfig`] (or directly from a URL and
/// passphrase) and hand it to code under test in place of a real client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MockNetworkClient {
    rpc_url: String,
    network_passphrase: String,
}

impl MockNetworkClient {
    /// Builds a mock client from an explicit RPC URL and passphrase.
    pub fn new(rpc_url: impl Into<String>, network_passphrase: impl Into<String>) -> Self {
        Self {
            rpc_url: rpc_url.into(),
            network_passphrase: network_passphrase.into(),
        }
    }

    /// Builds a mock client from a resolved [`NetworkConfig`].
    pub fn from_config(config: &NetworkConfig) -> Self {
        Self::new(config.rpc_url.clone(), config.network_passphrase.clone())
    }
}

impl NetworkClient for MockNetworkClient {
    fn rpc_url(&self) -> &str {
        &self.rpc_url
    }

    fn network_passphrase(&self) -> &str {
        &self.network_passphrase
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_every_documented_network_name_and_its_aliases() {
        for name in [
            "testnet",
            "futurenet",
            "mainnet",
            "pubnet",
            "local",
            "standalone",
            "TESTNET",
        ] {
            resolve_network(name).unwrap_or_else(|e| panic!("resolve_network({name:?}): {e}"));
        }
    }

    #[test]
    fn mainnet_and_pubnet_resolve_to_the_same_network() {
        assert_eq!(
            resolve_network("mainnet").unwrap(),
            resolve_network("pubnet").unwrap()
        );
    }

    #[test]
    fn rejects_an_unknown_network_name_with_a_clear_message() {
        let err = resolve_network("nonexistent-net").unwrap_err();
        assert!(err.contains("nonexistent-net"));
        assert!(err.contains("testnet"));
    }

    #[test]
    fn different_networks_resolve_to_different_endpoints() {
        let testnet = resolve_network("testnet").unwrap();
        let futurenet = resolve_network("futurenet").unwrap();
        assert_ne!(testnet.rpc_url, futurenet.rpc_url);
        assert_ne!(testnet.network_passphrase, futurenet.network_passphrase);
    }

    #[test]
    fn mock_client_exposes_the_url_and_passphrase_it_was_built_with() {
        let client = MockNetworkClient::new("http://localhost:8000/soroban/rpc", "Standalone");
        assert_eq!(client.rpc_url(), "http://localhost:8000/soroban/rpc");
        assert_eq!(client.network_passphrase(), "Standalone");
    }

    #[test]
    fn mock_client_can_be_built_from_a_resolved_network_config() {
        let config = resolve_network("testnet").unwrap();
        let client = MockNetworkClient::from_config(&config);
        assert_eq!(client.rpc_url(), config.rpc_url);
        assert_eq!(client.network_passphrase(), config.network_passphrase);
    }

    #[test]
    fn mock_client_satisfies_the_network_client_trait() {
        fn takes_client(client: &dyn NetworkClient) -> (String, String) {
            (
                client.rpc_url().to_string(),
                client.network_passphrase().to_string(),
            )
        }

        let config = resolve_network("futurenet").unwrap();
        let client = MockNetworkClient::from_config(&config);
        let (url, passphrase) = takes_client(&client);
        assert_eq!(url, config.rpc_url);
        assert_eq!(passphrase, config.network_passphrase);
    }

    #[test]
    fn toml_config_deserializes_all_fields() {
        let toml = r#"
            default_network = "testnet"
            rpc_url = "https://example.com/rpc"
            network_passphrase = "Test SDF Network ; September 2015"
        "#;
        let config: TomlConfig = toml::from_str(toml).unwrap();
        assert_eq!(config.default_network, Some("testnet".to_string()));
        assert_eq!(config.rpc_url, Some("https://example.com/rpc".to_string()));
        assert_eq!(
            config.network_passphrase,
            Some("Test SDF Network ; September 2015".to_string())
        );
    }

    #[test]
    fn toml_config_allows_partial_fields() {
        let toml = r#"
            default_network = "futurenet"
        "#;
        let config: TomlConfig = toml::from_str(toml).unwrap();
        assert_eq!(config.default_network, Some("futurenet".to_string()));
        assert!(config.rpc_url.is_none());
        assert!(config.network_passphrase.is_none());
    }

    #[test]
    fn toml_config_ignores_unknown_fields() {
        let toml = r#"
            default_network = "local"
            unknown_field = "ignore me"
        "#;
        let config: TomlConfig = toml::from_str(toml).unwrap();
        assert_eq!(config.default_network, Some("local".to_string()));
    }

    #[test]
    fn toml_config_default_is_empty() {
        let config = TomlConfig::default();
        assert!(config.default_network.is_none());
        assert!(config.rpc_url.is_none());
        assert!(config.network_passphrase.is_none());
    }
}
