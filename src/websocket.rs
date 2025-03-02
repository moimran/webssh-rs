use axum::extract::ws::{Message, WebSocket};
use bytes::Bytes;
use futures::{sink::SinkExt, stream::StreamExt};
use serde::Deserialize;
use tokio::sync::mpsc;
use tracing::{error, info, debug};

#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
pub enum WSCommand {
    #[serde(rename = "resize")]
    Resize { rows: u32, cols: u32 },
    #[serde(rename = "input")]
    Input { data: String },
}

pub struct WebSocketHandler {
    socket: WebSocket,
    ssh_input_tx: mpsc::Sender<Bytes>,
    ssh_output_rx: mpsc::Receiver<Bytes>,
}

impl WebSocketHandler {
    pub fn new(
        socket: WebSocket,
        ssh_input_tx: mpsc::Sender<Bytes>,
        ssh_output_rx: mpsc::Receiver<Bytes>,
    ) -> Self {
        Self {
            socket,
            ssh_input_tx,
            ssh_output_rx,
        }
    }

    pub async fn handle(mut self) {
        debug!("Starting WebSocket handler");
        let (mut ws_sender, mut ws_receiver) = self.socket.split();

        // Handle incoming WebSocket messages
        let ssh_input_tx = self.ssh_input_tx.clone();
        tokio::spawn(async move {
            debug!("Starting WebSocket receiver task");
            while let Some(Ok(msg)) = ws_receiver.next().await {
                match msg {
                    Message::Text(text) => {
                        debug!("Received text message: {}", text);
                        if let Ok(cmd) = serde_json::from_str::<WSCommand>(&text) {
                            match cmd {
                                WSCommand::Input { data } => {
                                    debug!("Processing input command: {} bytes", data.len());
                                    if let Err(e) = ssh_input_tx.send(Bytes::from(data)).await {
                                        error!("Failed to send SSH input: {}", e);
                                        break;
                                    }
                                }
                                WSCommand::Resize { rows, cols } => {
                                    debug!("Processing resize command: {}x{}", cols, rows);
                                    // Send ANSI escape sequence for window resize
                                    let resize_cmd = format!("\x1b[8;{};{}t", rows, cols);
                                    if let Err(e) = ssh_input_tx.send(Bytes::from(resize_cmd)).await {
                                        error!("Failed to send resize command: {}", e);
                                    }
                                }
                            }
                        } else {
                            error!("Failed to parse WebSocket command: {}", text);
                        }
                    }
                    Message::Binary(data) => {
                        debug!("Received binary message: {} bytes", data.len());
                        if let Err(e) = ssh_input_tx.send(Bytes::from(data)).await {
                            error!("Failed to send SSH binary input: {}", e);
                            break;
                        }
                    }
                    Message::Close(_) => {
                        info!("WebSocket close message received");
                        break;
                    }
                    msg => {
                        debug!("Received other message type: {:?}", msg);
                    }
                }
            }
            debug!("WebSocket receiver task ended");
        });

        // Forward SSH output to WebSocket
        debug!("Starting SSH output forwarder");
        while let Some(data) = self.ssh_output_rx.recv().await {
            debug!("Received {} bytes from SSH", data.len());
            match ws_sender.send(Message::Binary(data.to_vec())).await {
                Ok(_) => debug!("Sent {} bytes to WebSocket", data.len()),
                Err(e) => {
                    error!("Failed to send WebSocket message: {}", e);
                    break;
                }
            }
        }
        debug!("SSH output forwarder ended");
    }
}
