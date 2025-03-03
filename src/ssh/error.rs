use thiserror::Error;

/// Custom error types for SSH operations
#[derive(Error, Debug)]
pub enum SSHError {
    /// Errors related to network connections
    #[error("SSH connection error: {0}")]
    Connection(#[from] std::io::Error),
    
    /// Errors from the SSH2 library
    #[error("SSH error: {0}")]
    SSH(#[from] ssh2::Error),
    
    /// Authentication-specific errors
    #[error("SSH authentication error: {0}")]
    Authentication(String),
}
