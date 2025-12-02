use actix_files::Files;
use actix_web::{post, web, App, HttpResponse, HttpServer, Responder};
use serde::Deserialize;
use sqlx::mysql::MySqlPoolOptions;
use bcrypt::{hash, verify};

// --------- Request DTOs -----------

#[derive(Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

#[derive(Deserialize)]
struct RegisterRequest {
    username: String,
    password: String,
    email: String,
}

#[derive(Deserialize)]
struct WebAuthnStartRequest {
    username: String,
}

#[derive(Deserialize)]
struct WebAuthnFinishRequest {
    username: String,
    credential: serde_json::Value,
}

// --------- Endpoint Handlers -----------

#[post("/register")]
async fn register(
    db: web::Data<sqlx::MySqlPool>,
    req: web::Json<RegisterRequest>,
) -> impl Responder {
    // Check if username exists
    let existing_user: Option<(i32,)> = sqlx::query_as("SELECT id FROM users WHERE username = ?")
        .bind(&req.username)
        .fetch_optional(db.get_ref())
        .await
        .unwrap();

    if existing_user.is_some() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Username already exists"
        }));
    }

    // Hash password
    let password_hash = hash(&req.password, 12).unwrap();

    // Insert new user
    sqlx::query("INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)")
        .bind(&req.username)
        .bind(&req.email)
        .bind(password_hash)
        .execute(db.get_ref())
        .await
        .unwrap();

    HttpResponse::Ok().json(serde_json::json!({
        "status": "ok",
        "message": "User registered"
    }))
}

#[post("/login")]
async fn login(
    db: web::Data<sqlx::MySqlPool>,
    req: web::Json<LoginRequest>,
) -> impl Responder {
    let row = sqlx::query!("SELECT id, password_hash FROM users WHERE username = ?", req.username)
        .fetch_optional(db.get_ref())
        .await
        .unwrap();

    let row = match row {
        Some(r) => r,
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Invalid user"})),
    };

    // Check password
    let matches = verify(&req.password, &row.password_hash.unwrap_or_default()).unwrap_or(false);
    if !matches {
        return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Invalid password"}));
    }

    HttpResponse::Ok().json(serde_json::json!({
        "status": "ok",
        "user_id": row.id
    }))
}

// --------- WebAuthn placeholders -----------

#[post("/webauthn/start")]
async fn webauthn_start(req: web::Json<WebAuthnStartRequest>) -> impl Responder {
    println!("WebAuthn start for user: {}", req.username);

    HttpResponse::Ok().json(serde_json::json!({
        "status": "ok",
        "options": "webauthn-start-placeholder"
    }))
}

#[post("/webauthn/finish")]
async fn webauthn_finish(req: web::Json<WebAuthnFinishRequest>) -> impl Responder {
    println!("WebAuthn finish for user: {}", req.username);

    HttpResponse::Ok().json(serde_json::json!({
        "status": "ok",
        "message": "webauthn-finish-placeholder"
    }))
}

// --------- App + Static Files -----------

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    println!("Auth server running at http://127.0.0.1:8080");

    // MySQL pool
    let db = MySqlPoolOptions::new()
        .max_connections(5)
        .connect("mysql://username:password@localhost/Proxy_Authenticator_DB")
        .await
        .expect("Cannot connect to DB");

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(db.clone()))
            .service(Files::new("/static", "frontend").show_files_listing())
            .service(register)
            .service(login)
            .service(webauthn_start)
            .service(webauthn_finish)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
