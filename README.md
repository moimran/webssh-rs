# WebSSH-RS

A web-based SSH client written in Rust, using the ssh2 crate for SSH connections and Axum for the web server. This is a Rust implementation of the original Python WebSSH project.

## Features

- SSH password authentication support (including empty password)
- SSH public-key authentication support (RSA, DSA, ECDSA, Ed25519 keys)
- Encrypted keys support
- Fullscreen terminal support
- Resizable terminal window
- Auto-detect SSH server's default encoding
- Modern browser support (Chrome, Firefox, Safari, Edge, Opera)

## Requirements

- Rust 1.70 or higher
- OpenSSL development libraries

## Quick Start

1. Install the required dependencies:
   ```bash
   # Ubuntu/Debian
   sudo apt-get install pkg-config libssl-dev

   # Fedora/RHEL
   sudo dnf install pkg-config openssl-devel
   ```

2. Build and run the application:
   ```bash
   cargo build --release
   cargo run --release
   ```

3. Open your browser and navigate to `http://127.0.0.1:8888`

4. Enter your SSH server details and connect

## Server Options

```bash
# Start server with custom address and port
webssh-rs --address 0.0.0.0 --port 8000

# Start with TLS (HTTPS)
webssh-rs --tls --cert /path/to/cert.pem --key /path/to/key.pem

# Set logging level
webssh-rs --log-level debug
```

## Browser Support

The web interface uses xterm.js for terminal emulation and supports all modern browsers including:
- Chrome/Chromium
- Firefox
- Safari
- Edge
- Opera

## Security

- All passwords and sensitive data are only stored in memory during the session
- TLS support for secure HTTPS connections
- No permanent storage of credentials
- Proper handling of SSH host key verification

## License

This project is licensed under the same terms as the original Python WebSSH project.
