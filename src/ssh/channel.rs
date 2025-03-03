use ssh2::Session;
use tracing::{debug, error};

use crate::settings::SSHSettings;
use super::error::SSHError;

/// Sets up a standard SSH session channel with default terminal settings
/// 
/// This is the primary approach for most SSH servers and works with standard
/// Linux/Unix systems.
pub fn setup_standard_session(session: &mut Session, settings: &SSHSettings) -> Result<ssh2::Channel, SSHError> {
    debug!("Creating SSH channel for standard session");
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
    
    // Request PTY with standard terminal type
    debug!("Requesting PTY with standard terminal type");
    match channel.request_pty(
        &settings.terminal.standard_terminal_type, 
        None, 
        Some((settings.terminal.default_cols, settings.terminal.default_rows, 0, 0))
    ) {
        Ok(_) => debug!("PTY requested successfully"),
        Err(e) => {
            error!("Failed to request PTY: {}", e);
            return Err(e.into());
        }
    }
    
    // Start shell - this works for most devices
    debug!("Starting shell");
    match channel.shell() {
        Ok(_) => {
            debug!("Shell started successfully");
            Ok(channel)
        },
        Err(e) => {
            error!("Failed to start shell: {}", e);
            Err(e.into())
        }
    }
}

/// Sets up an SSH session channel specifically for Linux systems
/// 
/// This approach attempts to execute bash as the shell, which is
/// specific to Linux systems.
pub fn setup_linux_session(session: &mut Session, settings: &SSHSettings) -> Result<ssh2::Channel, SSHError> {
    debug!("Creating SSH channel for Linux session");
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
    
    // For Linux devices, we'll use the Linux terminal type from settings
    debug!("Requesting PTY for Linux device");
    match channel.request_pty(
        &settings.terminal.linux_terminal_type, 
        None, 
        Some((settings.terminal.default_cols, settings.terminal.default_rows, 0, 0))
    ) {
        Ok(_) => debug!("PTY requested successfully"),
        Err(e) => {
            error!("Failed to request PTY: {}", e);
            // Try with a simpler terminal type as fallback
            match channel.request_pty(
                &settings.terminal.fallback_terminal_type, 
                None, 
                Some((settings.terminal.default_cols, settings.terminal.default_rows, 0, 0))
            ) {
                Ok(_) => debug!("Dumb PTY requested successfully"),
                Err(e2) => {
                    error!("Failed to request dumb PTY: {}", e2);
                    // Don't try more fallbacks - if PTY fails, it's likely a protocol issue
                    return Err(e.into());
                }
            }
        }
    }
    
    // Try executing bash command - this is the key test for Linux devices
    debug!("Executing bash command for Linux device");
    match channel.exec("bash") {
        Ok(_) => {
            debug!("Bash command executed successfully - confirmed Linux device");
            Ok(channel)
        },
        Err(e) => {
            error!("Failed to execute bash command: {}", e);
            Err(e.into())
        }
    }
}

/// Sets up an SSH session channel specifically for Cisco network devices
/// 
/// Cisco devices often have different terminal requirements and behaviors
/// compared to standard Linux/Unix systems.
pub fn setup_cisco_session(session: &mut Session, settings: &SSHSettings) -> Result<ssh2::Channel, SSHError> {
    debug!("Creating SSH channel for Cisco session");
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
    
    // For Cisco devices, we'll use the standard terminal type from settings
    debug!("Requesting PTY for Cisco device");
    match channel.request_pty(
        &settings.terminal.standard_terminal_type, 
        None, 
        Some((settings.terminal.default_cols, settings.terminal.default_rows, 0, 0))
    ) {
        Ok(_) => debug!("PTY requested successfully"),
        Err(e) => {
            error!("Failed to request PTY: {}", e);
            return Err(e.into());
        }
    }
    
    // Start shell directly for Cisco devices
    debug!("Starting shell for Cisco device");
    match channel.shell() {
        Ok(_) => {
            debug!("Shell started successfully");
            Ok(channel)
        },
        Err(e) => {
            error!("Failed to start shell: {}", e);
            Err(e.into())
        }
    }
}
