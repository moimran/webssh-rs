use ssh2::Session;
use std::{io::{Read, Write}, net::TcpStream};
use tokio::sync::mpsc;
use bytes::Bytes;
use thiserror::Error;
use tracing::{error, info, debug};
use std::time::Duration;

// Define device types
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DeviceType {
    Linux,
    Cisco,
    Unknown,
}

// Function to detect device type based on hostname or other characteristics
fn detect_device_type(hostname: &str, port: u16) -> DeviceType {
    // Common Cisco device IP patterns (e.g., 192.168.0.x where x is 1-20)
    let is_likely_cisco_ip = hostname.starts_with("192.168.") && 
                             hostname.split('.').nth(3)
                                .and_then(|s| s.parse::<u16>().ok())
                                .map_or(false, |n| n <= 20);
    
    // Check for Cisco-specific hostnames or IP patterns
    if hostname.contains("cisco") || 
       hostname.contains("router") || 
       hostname.contains("switch") ||
       is_likely_cisco_ip ||
       // Common Cisco management ports
       (port == 22 && (hostname.ends_with(".1") || hostname.ends_with(".254")))
    {
        DeviceType::Cisco
    } 
    // Check for Linux-specific hostnames
    else if hostname.contains("linux") || 
            hostname.contains("ubuntu") || 
            hostname.contains("debian") || 
            hostname.contains("centos") || 
            hostname.contains("fedora") ||
            hostname.contains("server")
    {
        DeviceType::Linux
    } else {
        // Default to Unknown, we'll try to detect during connection
        DeviceType::Unknown
    }
}

// Helper function to create a session channel with retries
fn create_session_channel_with_retries(
    session: &mut Session,
    max_attempts: usize,
    retry_delay_ms: u64,
) -> Result<ssh2::Channel, SSHError> {
    for attempt in 1..=max_attempts {
        debug!("Session channel creation attempt {}/{}", attempt, max_attempts);
        match session.channel_session() {
            Ok(channel) => {
                debug!("Session channel created successfully on attempt {}", attempt);
                return Ok(channel);
            },
            Err(e) => {
                if attempt == max_attempts {
                    error!("Failed to create session channel after {} attempts: {}", max_attempts, e);
                    return Err(e.into());
                } else {
                    debug!("Session channel creation failed on attempt {}: {}", attempt, e);
                    std::thread::sleep(std::time::Duration::from_millis(retry_delay_ms));
                }
            }
        }
    }
    
    // This should never be reached due to the return in the loop above
    Err(SSHError::Connection(std::io::Error::new(
        std::io::ErrorKind::Other,
        "Failed to create session channel after retries"
    )))
}

#[derive(Error, Debug)]
pub enum SSHError {
    #[error("SSH connection error: {0}")]
    Connection(#[from] std::io::Error),
    #[error("SSH error: {0}")]
    SSH(#[from] ssh2::Error),
    #[error("SSH authentication error: {0}")]
    Authentication(String),
}

pub struct SSHSession {
    session: Session,
    channel: ssh2::Channel,
    resize_rx: Option<mpsc::Receiver<(u32, u32)>>,
}

impl SSHSession {
pub fn new(
    hostname: &str,
    port: u16,
    username: &str,
    password: Option<&str>,
    private_key: Option<&str>,
    device_type_hint: Option<&str>,
) -> Result<Self, SSHError> {
        info!("Connecting to SSH server {}:{}", hostname, port);
        
        // Create TCP connection with timeout
        let tcp = TcpStream::connect((hostname, port))?;
        tcp.set_read_timeout(Some(Duration::from_secs(30)))?;
        tcp.set_write_timeout(Some(Duration::from_secs(30)))?;
        debug!("TCP connection established");

        // Create and configure SSH session
        let mut session = Session::new()
            .map_err(|_| SSHError::Connection(
                std::io::Error::new(std::io::ErrorKind::Other, "Failed to create SSH session")
            ))?;

        session.set_tcp_stream(tcp);
        session.set_timeout(60000); // Increase timeout to 60 seconds
        session.set_compress(false); // Disable compression to avoid protocol issues
        
        // Configure for a wide range of SSH servers (both older and newer)
        session.method_pref(
            ssh2::MethodType::Kex,
            "curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1"
        )?;
        session.method_pref(
            ssh2::MethodType::HostKey,
            "ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,rsa-sha2-512,rsa-sha2-256,ssh-rsa,ssh-dss"
        )?;
        session.method_pref(
            ssh2::MethodType::CryptCs,
            "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr,aes256-cbc,aes192-cbc,aes128-cbc,3des-cbc"
        )?;
        session.method_pref(
            ssh2::MethodType::CryptSc,
            "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr,aes256-cbc,aes192-cbc,aes128-cbc,3des-cbc"
        )?;
        session.method_pref(
            ssh2::MethodType::MacCs,
            "hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1"
        )?;
        session.method_pref(
            ssh2::MethodType::MacSc,
            "hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1"
        )?;
        
        // Note: ssh2 doesn't have a direct way to set compression method preferences
        // We've already disabled compression with session.set_compress(false)

        debug!("Starting SSH handshake");
        
        // Log available methods before handshake
        // Note: These might not be available until after the handshake
        debug!("Configured KEX methods: curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1");
        debug!("Configured host key methods: ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,rsa-sha2-512,rsa-sha2-256,ssh-rsa,ssh-dss");
        debug!("Configured client->server encryption methods: chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr,aes256-cbc,aes192-cbc,aes128-cbc,3des-cbc");
        debug!("Configured server->client encryption methods: chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr,aes256-cbc,aes192-cbc,aes128-cbc,3des-cbc");
        
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
        session.set_keepalive(true, 30);

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

        // Detect device type, using hint if provided
        let device_type = if let Some(hint) = device_type_hint {
            match hint.to_lowercase().as_str() {
                "cisco" | "router" | "switch" => DeviceType::Cisco,
                "linux" | "ubuntu" | "debian" => DeviceType::Linux,
                _ => detect_device_type(hostname, port),
            }
        } else {
            detect_device_type(hostname, port)
        };
        debug!("Using device type: {:?}", device_type);
        
        // Create a simple channel
        info!("Creating SSH channel");
        
        // Set a longer timeout for channel operations (2 minutes)
        session.set_timeout(120000);
        
        // Create a simple session channel
        debug!("Creating SSH channel");
        let mut channel = match session.channel_session() {
            Ok(channel) => {
                debug!("SSH session channel opened successfully");
                channel
            },
            Err(e) => {
                error!("Failed to open session channel: {}", e);
                return Err(e.into());
            }
        };
        
        // Set up the session based on device type
        match device_type {
            DeviceType::Cisco => {
                // Cisco devices work better with the original approach
                debug!("Setting up session for Cisco device");
                
                // For Cisco devices, we'll use xterm and just start a shell
                debug!("Requesting PTY for Cisco device");
                match channel.request_pty("xterm", None, Some((80, 24, 0, 0))) {
                    Ok(_) => debug!("PTY requested successfully"),
                    Err(e) => {
                        error!("Failed to request PTY: {}", e);
                        return Err(e.into());
                    }
                }
                
                // Start shell directly for Cisco devices
                debug!("Starting shell for Cisco device");
                match channel.shell() {
                    Ok(_) => debug!("Shell started successfully"),
                    Err(e) => {
                        error!("Failed to start shell: {}", e);
                        return Err(e.into());
                    }
                }
            },
            DeviceType::Linux | DeviceType::Unknown => {
                // Linux devices work better with the new approach
                debug!("Setting up session for Linux/Unknown device");
                
                // For Linux devices, we'll use vt100 and try to execute bash
                debug!("Requesting PTY for Linux/Unknown device");
                match channel.request_pty("vt100", None, Some((80, 24, 0, 0))) {
                    Ok(_) => debug!("PTY requested successfully"),
                    Err(e) => {
                        error!("Failed to request PTY: {}", e);
                        // Try with a simpler terminal type as fallback
                        match channel.request_pty("dumb", None, Some((80, 24, 0, 0))) {
                            Ok(_) => debug!("Dumb PTY requested successfully"),
                            Err(e2) => {
                                error!("Failed to request dumb PTY: {}", e2);
                                // Don't try more fallbacks - if PTY fails, it's likely a protocol issue
                                return Err(e.into());
                            }
                        }
                    }
                }
                
                // Try executing a command instead of starting a shell for Linux devices
                debug!("Executing command for Linux/Unknown device");
                match channel.exec("bash") {
                    Ok(_) => debug!("Command executed successfully"),
                    Err(e) => {
                        error!("Failed to execute command: {}", e);
                        // Try starting a shell as fallback
                        match channel.shell() {
                            Ok(_) => debug!("Shell started successfully"),
                            Err(e2) => {
                                error!("Failed to start shell: {}", e2);
                                return Err(e.into());
                            }
                        }
                    }
                }
            }
        }
        
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
        })
    }

    pub fn set_resize_channel(&mut self, resize_rx: mpsc::Receiver<(u32, u32)>) {
        self.resize_rx = Some(resize_rx);
    }

    pub fn resize_pty(&mut self, rows: u32, cols: u32) -> Result<(), SSHError> {
        debug!("Resizing PTY to {}x{}", cols, rows);
        self.channel.request_pty_size(cols as u32, rows as u32, None, None)?;
        Ok(())
    }

    pub fn start_io(
        mut self,
        mut input_rx: mpsc::Receiver<Bytes>,
        output_tx: mpsc::Sender<Bytes>,
    ) -> Result<(), SSHError> {
        info!("Starting SSH I/O handling");
        
        // Buffer for reading from SSH
        let mut buf = [0u8; 4096];
        let mut last_keepalive = std::time::Instant::now();
        
        // Function to clean control sequences
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
        
        // Take ownership of the resize channel if it exists
        let mut resize_rx = self.resize_rx.take();
        
        loop {
            // Send keepalive every 30 seconds
            if last_keepalive.elapsed() >= std::time::Duration::from_secs(30) {
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
                        let cleaned_data = clean_control_sequences(&buf[..n]);
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
}
