mod ssh;
mod websocket;

use axum::{
    extract::{
        ws::{WebSocket, WebSocketUpgrade},
        State,
    },
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use tower_http::services::ServeDir;
use tracing::{error, info, Level};
use tracing_subscriber::FmtSubscriber;

use crate::{ssh::SSHSession, websocket::WebSocketHandler};

#[derive(Debug, Serialize, Deserialize)]
struct SSHCredentials {
    hostname: String,
    port: u16,
    username: String,
    password: Option<String>,
    private_key: Option<String>,
    device_type: Option<String>, // Optional field to explicitly specify device type
}

#[derive(Debug, Serialize, Deserialize)]
struct ConnectResponse {
    success: bool,
    message: String,
    session_id: Option<String>,
}

#[derive(Clone)]
struct AppState {
    sessions: Arc<Mutex<Vec<(String, SSHSession)>>>,
}

#[tokio::main]
async fn main() {
    // Initialize logging
    let _ = FmtSubscriber::builder()
        .with_max_level(Level::DEBUG)
        .with_level(true)
        .with_thread_ids(true)
        .with_target(true)
        .with_file(true)
        .with_line_number(true)
        .init();

    let state = AppState {
        sessions: Arc::new(Mutex::new(Vec::new())),
    };

    // Create router
    let app = Router::new()
        .route("/", get(index_handler))
        .route("/ws/:session_id", get(ws_handler))
        .route("/connect", post(connect_handler))
        .nest_service("/static", ServeDir::new("static"))
        .with_state(state);

    // Start server
    let addr = "127.0.0.1:8888";
    info!("Starting server on {}", addr);
    
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn index_handler() -> impl IntoResponse {
    Html(include_str!("../static/index.html"))
}

async fn connect_handler(
    State(state): State<AppState>,
    Json(credentials): Json<SSHCredentials>,
) -> Json<ConnectResponse> {
    match SSHSession::new(
        &credentials.hostname,
        credentials.port,
        &credentials.username,
        credentials.password.as_deref(),
        credentials.private_key.as_deref(),
        credentials.device_type.as_deref(),
    ) {
        Ok(session) => {
            let session_id = format!("{}-{}", credentials.hostname, uuid::Uuid::new_v4());
            state.sessions.lock().await.push((session_id.clone(), session));
            
            Json(ConnectResponse {
                success: true,
                message: "Connected successfully".to_string(),
                session_id: Some(session_id),
            })
        }
        Err(e) => {
            error!("SSH connection error: {}", e);
            Json(ConnectResponse {
                success: false,
                message: format!("Failed to connect: {}", e),
                session_id: None,
            })
        }
    }
}

async fn ws_handler(
    ws: WebSocketUpgrade,
    axum::extract::Path(session_id): axum::extract::Path<String>,
    State(state): State<AppState>,
) -> Response {
    let mut sessions = state.sessions.lock().await;
    
    if let Some(pos) = sessions.iter().position(|(id, _)| id == &session_id) {
        let (_, session) = sessions.remove(pos);
        info!("Starting WebSocket connection for session {}", session_id);
        ws.on_upgrade(move |socket| handle_socket(socket, session))
    } else {
        error!("Session {} not found", session_id);
        "Session not found".into_response()
    }
}

async fn handle_socket(socket: WebSocket, mut session: SSHSession) {
    // Create channels for SSH communication
    let (ssh_input_tx, ssh_input_rx) = mpsc::channel::<Bytes>(32);
    let (ssh_output_tx, ssh_output_rx) = mpsc::channel::<Bytes>(32);
    
    // Create resize channel
    let (resize_tx, resize_rx) = mpsc::channel::<(u32, u32)>(8);
    
    // Set resize channel on SSH session
    session.set_resize_channel(resize_rx);

    // Start SSH I/O in a separate thread
    tokio::task::spawn_blocking(move || {
        if let Err(e) = session.start_io(ssh_input_rx, ssh_output_tx) {
            error!("SSH I/O error: {}", e);
        }
    });

    // Create WebSocket handler
    let mut ws_handler = WebSocketHandler::new(socket, ssh_input_tx, ssh_output_rx);
    
    // Set resize channel on WebSocket handler
    ws_handler.set_resize_channel(resize_tx);
    
    // Start WebSocket handler
    ws_handler.handle().await;
}
