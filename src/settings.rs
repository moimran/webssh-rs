use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::Read;
use std::path::Path;
use tracing::{error, info};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settings {
    pub ssh: SSHSettings,
    pub server: ServerSettings,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerSettings {
    pub address: String,
    pub port: u16,
    pub tls_enabled: bool,
    pub cert_file: Option<String>,
    pub key_file: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SSHSettings {
    pub connection: ConnectionSettings,
    pub crypto: CryptoSettings,
    pub terminal: TerminalSettings,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionSettings {
    pub read_timeout_seconds: u64,
    pub write_timeout_seconds: u64,
    pub timeout_seconds: u64,
    pub channel_timeout_seconds: u64,
    pub keepalive_seconds: u64,
    pub compress: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoSettings {
    pub kex_algorithms: String,
    pub host_key_algorithms: String,
    pub encryption_client_to_server: String,
    pub encryption_server_to_client: String,
    pub mac_client_to_server: String,
    pub mac_server_to_client: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TerminalSettings {
    pub standard_terminal_type: String,
    pub linux_terminal_type: String,
    pub fallback_terminal_type: String,
    pub default_cols: u32,
    pub default_rows: u32,
}

impl Settings {
    pub fn load() -> Self {
        let config_path = Path::new("settings.json");
        if config_path.exists() {
            match Self::load_from_file(config_path) {
                Ok(settings) => {
                    info!("Loaded settings from settings.json");
                    return settings;
                }
                Err(e) => {
                    error!("Failed to load settings from file: {}", e);
                }
            }
        }

        info!("Using default settings");
        Self::default()
    }

    fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn std::error::Error>> {
        let mut file = File::open(path)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;
        let settings: Settings = serde_json::from_str(&contents)?;
        Ok(settings)
    }
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            ssh: SSHSettings {
                connection: ConnectionSettings {
                    read_timeout_seconds: 30,
                    write_timeout_seconds: 30,
                    timeout_seconds: 60,
                    channel_timeout_seconds: 120,
                    keepalive_seconds: 30,
                    compress: false,
                },
                crypto: CryptoSettings {
                    kex_algorithms: "curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1".to_string(),
                    host_key_algorithms: "ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,rsa-sha2-512,rsa-sha2-256,ssh-rsa,ssh-dss".to_string(),
                    encryption_client_to_server: "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr,aes256-cbc,aes192-cbc,aes128-cbc,3des-cbc".to_string(),
                    encryption_server_to_client: "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr,aes256-cbc,aes192-cbc,aes128-cbc,3des-cbc".to_string(),
                    mac_client_to_server: "hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1".to_string(),
                    mac_server_to_client: "hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1".to_string(),
                },
                terminal: TerminalSettings {
                    standard_terminal_type: "xterm".to_string(),
                    linux_terminal_type: "vt100".to_string(),
                    fallback_terminal_type: "dumb".to_string(),
                    default_cols: 80,
                    default_rows: 24,
                },
            },
            server: ServerSettings {
                address: "127.0.0.1".to_string(),
                port: 8888,
                tls_enabled: false,
                cert_file: None,
                key_file: None,
            },
        }
    }
}
