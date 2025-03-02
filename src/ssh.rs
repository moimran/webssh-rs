use ssh2::Session;
use std::{io::{Read, Write}, net::TcpStream};
use tokio::sync::mpsc;
use bytes::Bytes;
use thiserror::Error;
use tracing::{error, info, debug};
use std::time::Duration;

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
}

impl SSHSession {
    pub fn new(
        hostname: &str,
        port: u16,
        username: &str,
        password: Option<&str>,
        private_key: Option<&str>,
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
        session.set_compress(true);
        
        // Configure for older SSH servers
        session.method_pref(
            ssh2::MethodType::Kex,
            "diffie-hellman-group1-sha1,diffie-hellman-group14-sha1"
        )?;
        session.method_pref(
            ssh2::MethodType::HostKey,
            "ssh-rsa,ssh-dss"
        )?;

        debug!("Starting SSH handshake");
        session.handshake()?;
        debug!("SSH handshake completed");

        // Configure session
        session.set_blocking(true);
        session.set_keepalive(true, 30);

        // Authenticate
        if let Some(password) = password {
            info!("Authenticating with password for user {}", username);
            session.userauth_password(username, password)?;
        } else if let Some(_key) = private_key {
            // TODO: Implement private key authentication
            return Err(SSHError::Authentication("Private key auth not implemented".into()));
        } else {
            return Err(SSHError::Authentication("No authentication method provided".into()));
        }

        if !session.authenticated() {
            return Err(SSHError::Authentication("Authentication failed".into()));
        }
        debug!("Authentication successful");

        // Create channel
        info!("Creating SSH channel");
        let mut channel = session.channel_session()?;
        
        // Set up the PTY
        debug!("Requesting PTY");
        channel.request_pty("dumb", None, Some((80, 24, 0, 0)))?;
        
        // Start shell
        debug!("Starting shell");
        channel.shell()?;
        
        // Ensure channel is ready
        debug!("Flushing channel");
        channel.flush()?;

        // Set session to non-blocking mode for I/O
        session.set_blocking(false);
        debug!("SSH session setup completed");

        Ok(Self { 
            session,
            channel,
        })
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
