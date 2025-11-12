use axum::{Router, routing::post, extract::State, extract::Json, response::Redirect};
use mysql::*;
use mysql::prelude::*;
use serde::Deserialize;
use std::sync::Arc;
use webauthn_rs::prelude::*;
use std::net::SocketAddr;
use hyper::server::Server;
use anyhow::Result;

#[derive(Clone)]
struct AppState {
    pool: Pool,
    webauthn: Webauthn,
}

#[derive(Deserialize)]
struct LoginRequest {
    username: String,
}

pub async fn run_auth_server() -> Result<()> {
    // MySQL connection pool
    let pool = Pool::new("mysql://root:password@localhost:3307")?;

    // Initialize WebAuthn
    let webauthn = WebauthnBuilder::new("proto_auth_app.com", "Proto Auth App")
        .set_origin("https://auth.proto_auth_app.com")
        .build()?;

    let state = Arc::new(AppState { pool, webauthn });

    // Build Axum router
    let app = Router::new()
        .route("/login", post(login_handler))
        .route("/register", post(register_handler))
        .with_state(state);

    // Bind to address and run
    let addr: SocketAddr = "127.0.0.1:8081".parse()?;
    println!("Auth server running at http://{}", addr);
    Server::bind(&addr)
        .serve(app.into_make_service())
        .await?;

    Ok(())
}

async fn login_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<LoginRequest>,
) -> Result<Redirect, String> {
    let mut conn = state.pool.get_conn().map_err(|e| e.to_string())?;

    // Check if user exists
    let exists: Option<String> = conn
        .exec_first(
            "SELECT username FROM Proxy_Authenticator_DB.users WHERE username = ?",
            (req.username.clone(),),
        )
        .map_err(|e| e.to_string())?;

    if exists.is_some() {
        // TODO: Verify WebAuthn credentials
        Ok(Redirect::to("https://proto_auth_app.com/dashboard"))
    } else {
        // Login failed — redirect to failure page
        Ok(Redirect::to("https://auth.proto_auth_app.com/failed"))
    }
}

async fn register_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<LoginRequest>,
) -> Result<Json<serde_json::Value>, String> {
    let mut conn = state.pool.get_conn().map_err(|e| e.to_string())?;

    // Insert new user
    conn.exec_drop(
        "INSERT INTO Proxy_Authenticator_DB.users (username) VALUES (?)",
        (req.username.clone(),),
    )
    .map_err(|e| e.to_string())?;

    Ok(Json(serde_json::json!({
        "status": "success",
        "message": "User registered"
    })))
}
