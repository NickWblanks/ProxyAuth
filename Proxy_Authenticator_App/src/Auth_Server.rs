use actix_web::{web, App, HttpServer, HttpResponse, Responder};
use serde::Deserialize;

// Temporary in-memory storage for demonstration (replace with DB later)
use std::sync::Mutex;
use lazy_static::lazy_static;

lazy_static! {
    static ref REGISTERED_USERS: Mutex<Vec<String>> = Mutex::new(Vec::new());
}

// --- Start the auth server ---
pub async fn start_auth_server() -> std::io::Result<()> {
    let addr = "127.0.0.1:8080";

    println!("Auth server running on http://{}", addr);

    HttpServer::new(|| {
        App::new()
            .route("/", web::get().to(root))
            .route("/register", web::post().to(register))
            .route("/login", web::post().to(login))
            .route("/webauthn/register", web::post().to(webauthn_register))
    })
    .bind(addr)?
    .run()
    .await
}

// --- Handlers ---

async fn root() -> impl Responder {
    HttpResponse::Ok().body("Hello from Auth Server!")
}

#[derive(Debug, Deserialize)]
struct RegisterRequest {
    username: String,
    email: String,
    // WebAuthn registration fields can go here
}

async fn register(form: web::Json<RegisterRequest>) -> impl Responder {
    // TODO: Save user info to database
    println!("Register request: {:?}", form);

    // Temporary: store username in memory
    REGISTERED_USERS.lock().unwrap().push(form.username.clone());

    HttpResponse::Ok().body(format!("User '{}' registered (stub)", form.username))
}

#[derive(Debug, Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
    // WebAuthn assertion fields can go here
}

async fn login(form: web::Json<LoginRequest>) -> impl Responder {
    // TODO: Check credentials or WebAuthn assertion
    println!("Login request: {:?}", form);

    // For now, just return success
    HttpResponse::Ok().body(format!("User '{}' logged in (stub)", form.username))
}

// --- WebAuthn registration endpoint ---

#[derive(Debug, Deserialize)]
struct WebAuthnRegisterRequest {
    username: String,
    challenge: String,
    // other WebAuthn fields like clientDataJSON, attestationObject
}

async fn webauthn_register(form: web::Json<WebAuthnRegisterRequest>) -> impl Responder {
    // TODO: Generate WebAuthn challenge, send to client, validate response
    println!("WebAuthn registration request: {:?}", form);

    // Temporary: store challenge in memory (stub)
    let challenge_result = format!("Received challenge for {}", form.username);

    HttpResponse::Ok().body(challenge_result)
}
