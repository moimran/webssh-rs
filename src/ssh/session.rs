use ssh2::Session;
use std::{io::{Read, Write}, net::TcpStream};
use tokio::sync::mpsc;
use bytes::Bytes;
use tracing::{error, info, debug};
use std::time::Duration;

use crate::settings::SSHSettings;
use super::error::SSHError;
use super::channel::{setup_standard_session, setup_linux_session, setup_cisco_session};

/// Represents an active SSH session with a remote server
/// 
/// This struct manages the SSH connection, authentication, and I/O operations
/// between the web client and the SSH server.
pub struct SSHSession {
    session: Session,
    channel: ssh2::Channel,
    resize_rx: Option<mpsc::Receiver<(u32, u32)>>,
    settings: SSHSettings,
}

impl SSHSession {
    /// Creates a new SSH session with the specified connection parameters
    ///
    /// # Arguments
    /// * `hostname` - The hostname or IP address of the SSH server
    /// * `port` - The port number of the SSH server (typically 22)
    /// * `username` - The username for authentication
    /// * `password` - Optional password for authentication
    /// * `private_key` - Optional private key for authentication (in PEM format)
    /// * `device_type_hint` - Optional hint about the device type (e.g., "cisco", "linux")
    /// * `settings` - SSH settings from the application configuration
    ///
    /// # Returns
    /// * `Result<Self, SSHError>` - A new SSHSession or an error
    pub fn new(
        hostname: &str,
        port: u16,
        username: &str,
        password: Option<&str>,
        private_key: Option<&str>,
        device_type_hint: Option<&str>,
        settings: &SSHSettings,
    ) -> Result<Self, SSHError> {
        info!("Connecting to SSH server {}:{}", hostname, port);
        
        // Create TCP connection with timeout
        let tcp = TcpStream::connect((hostname, port))?;
        tcp.set_read_timeout(Some(Duration::from_secs(settings.connection.read_timeout_seconds)))?;
        tcp.set_write_timeout(Some(Duration::from_secs(settings.connection.write_timeout_seconds)))?;
        debug!("TCP connection established");

        // Create and configure SSH session
        let mut session = Session::new()
            .map_err(|_| SSHError::Connection(
                std::io::Error::new(std::io::ErrorKind::Other, "Failed to create SSH session")
            ))?;

        session.set_tcp_stream(tcp);
        session.set_timeout((settings.connection.timeout_seconds * 1000) as u32); // Convert seconds to milliseconds
        session.set_compress(settings.connection.compress);
        
        // Configure SSH algorithms from settings
        session.method_pref(
            ssh2::MethodType::Kex,
            &settings.crypto.kex_algorithms
        )?;
        session.method_pref(
            ssh2::MethodType::HostKey,
            &settings.crypto.host_key_algorithms
        )?;
        session.method_pref(
            ssh2::MethodType::CryptCs,
            &settings.crypto.encryption_client_to_server
        )?;
        session.method_pref(
            ssh2::MethodType::CryptSc,
            &settings.crypto.encryption_server_to_client
        )?;
        session.method_pref(
            ssh2::MethodType::MacCs,
            &settings.crypto.mac_client_to_server
        )?;
        session.method_pref(
            ssh2::MethodType::MacSc,
            &settings.crypto.mac_server_to_client
        )?;

        debug!("Starting SSH handshake");
        
        // Log available methods before handshake
        debug!("Configured KEX methods: {}", settings.crypto.kex_algorithms);
        debug!("Configured host key methods: {}", settings.crypto.host_key_algorithms);
        debug!("Configured client->server encryption methods: {}", settings.crypto.encryption_client_to_server);
        debug!("Configured server->client encryption methods: {}", settings.crypto.encryption_server_to_client);
        
        // Perform handshake with detailed error handling
        match session.handshake() {
            Ok(_) => debug!("SSH handshake completed successfully"),
            Err(e) => {
                error!("SSH handshake failed: {}", e);
                error!("This could be due to incompatible encryption algorithms or network issues");
                return Err(e.into());
            }
        }

        // Configure session
        session.set_blocking(true);
        session.set_keepalive(true, settings.connection.keepalive_seconds as u32);

        // Authenticate
        if let Some(password) = password {
            info!("Authenticating with password for user {}", username);
            session.userauth_password(username, password)?;
        } else if let Some(key_data) = private_key {
            info!("Authenticating with private key for user {}", username);
            
            // Try to parse the private key
            debug!("Parsing private key");
            
            // First, check if the key is in PEM format
            if key_data.contains("-----BEGIN") {
                debug!("Key appears to be in PEM format");
                
                // Try to load the private key
                match session.userauth_pubkey_memory(username, None, key_data, None) {
                    Ok(_) => debug!("Private key authentication successful"),
                    Err(e) => {
                        error!("Private key authentication failed: {}", e);
                        return Err(SSHError::Authentication(format!("Private key authentication failed: {}", e)));
                    }
                }
            } else {
                // If not in PEM format, it might be in OpenSSH format or another format
                error!("Unsupported private key format. Please provide a PEM formatted private key");
                return Err(SSHError::Authentication("Unsupported private key format. Please provide a PEM formatted private key".into()));
            }
        } else {
            return Err(SSHError::Authentication("No authentication method provided".into()));
        }

        if !session.authenticated() {
            return Err(SSHError::Authentication("Authentication failed".into()));
        }
        debug!("Authentication successful");

        // Create a simple channel
        info!("Creating SSH channel");
        
        // Set a longer timeout for channel operations
        session.set_timeout((settings.connection.channel_timeout_seconds * 1000) as u32);
        
        // Get device type hint if provided
        let device_type_hint = device_type_hint.map(|hint| hint.to_lowercase());
        let is_cisco_hint = device_type_hint.as_ref().map_or(false, |hint| 
            hint == "cisco" || hint == "router" || hint == "switch");
        
        // Set up the channel based on device type with fallback mechanism
        let mut channel = if is_cisco_hint {
            debug!("Using Cisco approach based on user hint");
            setup_cisco_session(&mut session, settings)?
        } else {
            // Try standard approach first (similar to electerm)
            debug!("Trying standard approach first");
            match setup_standard_session(&mut session, settings) {
                Ok(channel) => {
                    debug!("Standard approach succeeded");
                    channel
                },
                Err(e) => {
                    debug!("Standard approach failed: {}. Trying Linux approach", e);
                    // If standard approach fails, try Linux approach
                    match setup_linux_session(&mut session, settings) {
                        Ok(channel) => {
                            debug!("Linux approach succeeded");
                            channel
                        },
                        Err(e) => {
                            debug!("Linux approach failed: {}. Trying Cisco approach as final fallback", e);
                            // If Linux approach fails, try Cisco approach as final fallback
                            setup_cisco_session(&mut session, settings)?
                        }
                    }
                }
            }
        };
        
        // Ensure channel is ready with a flush
        debug!("Flushing channel");
        if let Err(e) = channel.flush() {
            if e.kind() != std::io::ErrorKind::WouldBlock {
                error!("Failed to flush channel: {}", e);
                // Non-blocking errors are expected and can be ignored
            }
        }

        // Set session to non-blocking mode for I/O
        session.set_blocking(false);
        debug!("SSH session setup completed");

        Ok(Self { 
            session,
            channel,
            resize_rx: None,
            settings: settings.clone(),
        })
    }

    /// Sets the channel for receiving terminal resize events
    ///
    /// # Arguments
    /// * `resize_rx` - A receiver for (rows, cols) tuples
    pub fn set_resize_channel(&mut self, resize_rx: mpsc::Receiver<(u32, u32)>) {
        self.resize_rx = Some(resize_rx);
    }

    /// Resizes the PTY to the specified dimensions
    ///
    /// # Arguments
    /// * `rows` - Number of rows in the terminal
    /// * `cols` - Number of columns in the terminal
    ///
    /// # Returns
    /// * `Result<(), SSHError>` - Success or an error
    pub fn resize_pty(&mut self, rows: u32, cols: u32) -> Result<(), SSHError> {
        debug!("Resizing PTY to {}x{}", cols, rows);
        self.channel.request_pty_size(cols as u32, rows as u32, None, None)?;
        Ok(())
    }

    /// Starts the I/O handling between the SSH channel and the WebSocket
    ///
    /// This function runs in a separate thread and handles:
    /// - Reading data from the SSH channel and sending it to the WebSocket
    /// - Reading data from the WebSocket and sending it to the SSH channel
    /// - Processing terminal resize events
    /// - Sending keepalive packets
    ///
    /// # Arguments
    /// * `input_rx` - A receiver for data from the WebSocket
    /// * `output_tx` - A sender for data to the WebSocket
    ///
    /// # Returns
    /// * `Result<(), SSHError>` - Success or an error
    pub fn start_io(
        mut self,
        mut input_rx: mpsc::Receiver<Bytes>,
        output_tx: mpsc::Sender<Bytes>,
    ) -> Result<(), SSHError> {
        info!("Starting SSH I/O handling");
        
        // Buffer for reading from SSH
        let mut buf = [0u8; 4096];
        let mut last_keepalive = std::time::Instant::now();
        
        // Take ownership of the resize channel if it exists
        let mut resize_rx = self.resize_rx.take();
        
        loop {
            // Send keepalive based on settings
            if last_keepalive.elapsed() >= std::time::Duration::from_secs(self.settings.connection.keepalive_seconds) {
                debug!("Sending keepalive");
                if let Err(e) = self.session.keepalive_send() {
                    error!("Failed to send keepalive: {}", e);
                    break;
                }
                last_keepalive = std::time::Instant::now();
            }
            
            // Process any pending resize commands
            if let Some(ref mut rx) = resize_rx {
                while let Ok((rows, cols)) = rx.try_recv() {
                    debug!("Processing resize command: {}x{}", cols, rows);
                    if let Err(e) = self.resize_pty(rows, cols) {
                        error!("Failed to resize PTY: {}", e);
                    }
                }
            }

            // Read from SSH with timeout
            match self.channel.read(&mut buf) {
                Ok(n) => {
                    if n > 0 {
                        debug!("Read {} bytes from SSH", n);
                        // Clean control sequences from the output
                        let cleaned_data = Self::clean_control_sequences(&buf[..n]);
                        if !cleaned_data.is_empty() {
                            let data = Bytes::from(cleaned_data);
                            if output_tx.blocking_send(data).is_err() {
                                error!("Failed to send SSH output to WebSocket");
                                break;
                            }
                            debug!("Sent {} bytes to WebSocket", n);
                        }
                    } else if self.channel.eof() {
                        info!("SSH channel closed");
                        break;
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    // No data available, continue to process input
                }
                Err(e) => {
                    error!("SSH read error: {}", e);
                    return Err(SSHError::Connection(e));
                }
            }

            // Process any pending input
            while let Ok(data) = input_rx.try_recv() {
                debug!("Received {} bytes from WebSocket", data.len());
                match self.channel.write_all(&data) {
                    Ok(_) => {
                        if let Err(e) = self.channel.flush() {
                            if e.kind() != std::io::ErrorKind::WouldBlock {
                                error!("Failed to flush SSH channel: {}", e);
                                return Err(SSHError::Connection(e));
                            }
                        }
                        debug!("Wrote {} bytes to SSH", data.len());
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        // Would block, try again next iteration
                        break;
                    }
                    Err(e) => {
                        error!("SSH write error: {}", e);
                        return Err(SSHError::Connection(e));
                    }
                }
            }

            // Small delay to prevent busy-waiting
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        info!("SSH I/O handling completed");
        Ok(())
    }
    
    /// Cleans control sequences from terminal output
    ///
    /// This function removes ANSI escape sequences and other terminal control
    /// codes that might interfere with the web terminal display.
    ///
    /// # Arguments
    /// * `input` - The raw terminal output
    ///
    /// # Returns
    /// * `Vec<u8>` - The cleaned output
    fn clean_control_sequences(input: &[u8]) -> Vec<u8> {
        let mut output = Vec::with_capacity(input.len());
        let mut i = 0;
        
        while i < input.len() {
            if input[i] == b';' {
                // Check if this is part of a terminal code sequence (like ;37;295t)
                let mut is_terminal_code = false;
                let mut j = i + 1;
                while j < input.len() && j < i + 10 {  // Look ahead up to 10 chars
                    if input[j] == b't' {
                        is_terminal_code = true;
                        break;
                    }
                    j += 1;
                }
                if is_terminal_code {
                    // Skip until we find 't'
                    while i < input.len() && input[i] != b't' {
                        i += 1;
                    }
                    i += 1;  // Skip the 't'
                    continue;
                }
            }

            if input[i] == 0x1b {  // ESC
                // Skip escape sequence
                i += 1;
                if i < input.len() && input[i] == b'[' {
                    i += 1;
                    while i < input.len() {
                        let c = input[i];
                        if (c >= b'A' && c <= b'Z') || (c >= b'a' && c <= b'z') || c == b'@' {
                            i += 1;
                            break;
                        }
                        i += 1;
                    }
                }
            } else {
                output.push(input[i]);
                i += 1;
            }
        }
        
        // Clean up any remaining terminal codes at the end
        if let Some(pos) = output.iter().rposition(|&x| x == b';') {
            if output[pos..].iter().any(|&x| x == b't') {
                output.truncate(pos);
            }
        }
        
        output
    }
}
