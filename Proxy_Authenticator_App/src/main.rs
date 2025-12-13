use actix_cors::Cors;
use actix_files::Files;
use actix_web::{App, HttpResponse, HttpServer, Responder, web, HttpRequest};
use dotenv::dotenv;
use serde::{Deserialize, Serialize};
use sqlx::mysql::{MySqlConnectOptions, MySqlPool, MySqlSslMode};
use std::env;
use std::{collections::HashMap, str::FromStr, sync::Mutex};
use url::Url;
use uuid::Uuid;
use webauthn_rs::prelude::*;

// ---------------------------------------------------------------------------
// 1. App State & Helpers
// ---------------------------------------------------------------------------
struct AppState {
    db: MySqlPool,
    webauthn: Webauthn,
    // Store (User_ID_Int, Registration_State)
    reg_state_store: Mutex<HashMap<Uuid, (i32, PasskeyRegistration)>>,
    // Store (User_ID_Int, Authentication_State)
    auth_state_store: Mutex<HashMap<Uuid, (i32, PasskeyAuthentication)>>,
}

// HELPER: Convert MySQL INT ID -> Stable UUID for WebAuthn
fn id_to_uuid(id: i32) -> Uuid {
    Uuid::from_u128(id as u128)
}

fn read_env_var(key: &str) -> String {
    env::var(key).unwrap_or_else(|_| panic!("Environment variable {} not set", key))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();

    // 1. Database
    let db_options = MySqlConnectOptions::new()
        .host(read_env_var("DB_HOSTNAME").as_str())
        .port(
            read_env_var("DB_PORT")
                .parse::<u16>()
                .expect("Invalid port"),
        )
        .username(read_env_var("DB_USERNAME").as_str())
        .password(read_env_var("DB_PASSWORD").as_str())
        .database(read_env_var("DB_DATABASE").as_str())
        .ssl_mode(MySqlSslMode::Disabled);

    println!(" Connecting to Database...");
    let pool = MySqlPool::connect_with(db_options).await.expect("DB Fail");
    println!("Database Connected");
    // 2. WebAuthn Config
    // rp = relying party
    let rp_id = "localhost";
    let rp_origin = Url::parse("http://localhost").expect("Invalid URL");
    let builder = WebauthnBuilder::new(rp_id, &rp_origin).expect("Invalid config");
    let webauthn = builder.build().expect("Failed to build WebAuthn");

    let data = web::Data::new(AppState {
        db: pool,
        webauthn,
        reg_state_store: Mutex::new(HashMap::new()),
        auth_state_store: Mutex::new(HashMap::new()),
    });

    println!(" Server running at http://localhost:8080");

    HttpServer::new(move || {
        App::new()
            .app_data(data.clone())
            .wrap(Cors::permissive())
            // API Routes
            .route("/register", web::post().to(register_password))
            .route("/login", web::post().to(login_password))
            .route(
                "/webauthn/register/start",
                web::post().to(webauthn_register_start),
            )
            .route(
                "/webauthn/register/finish",
                web::post().to(webauthn_register_finish),
            )
            .route(
                "/webauthn/login/start",
                web::post().to(webauthn_login_start),
            )
            .route(
                "/webauthn/login/finish",
                web::post().to(webauthn_login_finish),
            )
            .route(
                "/cookie",
                web::post().to(store_cookie),
            )
            .route(
                "/auth",
                web::get().to(auth),
            )
    })
    .bind(("0.0.0.0", 8080))?
    .run()
    .await
}
// ---------------------------------------------------------------------------
// 2. Data Structs
// ---------------------------------------------------------------------------
#[derive(Deserialize)]
struct AuthRequest {
    username: String,
    email: Option<String>,
    password: Option<String>,
}

#[derive(Deserialize)]
struct RegisterFinishRequest {
    req_id: Uuid,
    register_response: RegisterPublicKeyCredential,
}

#[derive(Deserialize)]
struct LoginFinishRequest {
    req_id: Uuid,
    login_response: PublicKeyCredential,
}

#[derive(Deserialize)]
struct CookieRequest {
    auth_value: String,
    expires_at: String
}

// ---------------------------------------------------------------------------
// 3. Password Handlers
// ---------------------------------------------------------------------------

async fn register_password(
    data: web::Data<AppState>,
    body: web::Json<AuthRequest>,
) -> impl Responder {
    let password = body.password.as_ref().unwrap();
    let email = body.email.as_ref().unwrap();

    let hash = bcrypt::hash(password, bcrypt::DEFAULT_COST).unwrap();

    match sqlx::query!(
        "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
        body.username,
        email,
        hash
    )
    .execute(&data.db)
    .await
    {
        Ok(_) => HttpResponse::Ok().body("User registered"),
        Err(e) => HttpResponse::InternalServerError().body(format!("DB Error: {}", e)),
    }
}

async fn login_password(data: web::Data<AppState>, body: web::Json<AuthRequest>) -> impl Responder {
    let password = body.password.as_ref().unwrap();

    let user = sqlx::query!(
        "SELECT password_hash FROM users WHERE username = ?",
        body.username
    )
    .fetch_optional(&data.db)
    .await
    .unwrap_or(None);

    if let Some(u) = user {
        let valid = bcrypt::verify(password, &u.password_hash.unwrap_or_default()).unwrap_or(false);
        if valid {
            return HttpResponse::Ok().body("Login Successful");
        }
    }
    HttpResponse::Unauthorized().finish()
}

// ---------------------------------------------------------------------------
// 4. WebAuthn Handlers
// ---------------------------------------------------------------------------

async fn webauthn_register_start(
    data: web::Data<AppState>,
    body: web::Json<AuthRequest>,
) -> impl Responder {
    let user_record = sqlx::query!("SELECT id FROM users WHERE username = ?", body.username)
        .fetch_optional(&data.db)
        .await
        .unwrap_or(None);

    let user_id_int = match user_record {
        Some(u) => u.id,
        None => return HttpResponse::NotFound().body("User must exist first"),
    };

    let user_uuid = id_to_uuid(user_id_int);

    let (challenge, reg_state) = match data.webauthn.start_passkey_registration(
        user_uuid,
        &body.username,
        &body.username,
        None,
    ) {
        Ok(res) => res,
        Err(_) => return HttpResponse::InternalServerError().finish(),
    };

    let req_id = Uuid::new_v4();
    // Store User ID (int) with the state
    data.reg_state_store
        .lock()
        .unwrap()
        .insert(req_id, (user_id_int, reg_state));

    HttpResponse::Ok().json((req_id, challenge))
}

async fn webauthn_register_finish(
    data: web::Data<AppState>,
    body: web::Json<RegisterFinishRequest>,
) -> impl Responder {
    // FIX: Retrieve both ID and State at once. Do not call remove() twice.
    let (user_id_int, reg_state) = match data.reg_state_store.lock().unwrap().remove(&body.req_id) {
        Some(s) => s,
        None => return HttpResponse::BadRequest().body("Invalid session"),
    };

    let passkey = match data
        .webauthn
        .finish_passkey_registration(&body.register_response, &reg_state)
    {
        Ok(pk) => pk,
        Err(err) => return HttpResponse::BadRequest().body(err.to_string()),
    };

    let passkey_json = serde_json::to_value(&passkey).unwrap();
    // FIX: Use field access `.cred_id` not method `.cred_id()`
    let cred_id = passkey.cred_id().as_slice();

    match sqlx::query!(
        "UPDATE users SET credential_id = ?, passkey = ? WHERE id = ?",
        cred_id,
        passkey_json,
        user_id_int
    )
    .execute(&data.db)
    .await
    {
        Ok(_) => HttpResponse::Ok().body("WebAuthn Linked to Account"),
        Err(e) => HttpResponse::InternalServerError().body(format!("DB Error: {}", e)),
    }
}

async fn webauthn_login_start(
    data: web::Data<AppState>,
    body: web::Json<AuthRequest>,
) -> impl Responder {
    let user = sqlx::query!(
        "SELECT id, passkey FROM users WHERE username = ?",
        body.username
    )
    .fetch_optional(&data.db)
    .await
    .unwrap_or(None);

    let (user_id, passkey_json) = match user {
        Some(rec) => {
            if let Some(json) = rec.passkey {
                (rec.id, json)
            } else {
                return HttpResponse::NotFound().body("No passkey set for this user");
            }
        }
        None => return HttpResponse::NotFound().body("User not found"),
    };

    let passkey: Passkey = match serde_json::from_value(passkey_json) {
        Ok(p) => p,
        Err(_) => return HttpResponse::InternalServerError().body("Corrupt passkey data"),
    };

    let (challenge, auth_state) = match data.webauthn.start_passkey_authentication(&[passkey]) {
        Ok(res) => res,
        Err(_) => return HttpResponse::InternalServerError().finish(),
    };

    let req_id = Uuid::new_v4();
    // FIX: Use `user_id` here (which is an i32 extracted above)
    data.auth_state_store
        .lock()
        .unwrap()
        .insert(req_id, (user_id, auth_state));

    HttpResponse::Ok().json((req_id, challenge))
}

async fn webauthn_login_finish(
    data: web::Data<AppState>,
    body: web::Json<LoginFinishRequest>,
) -> impl Responder {
    let (user_id_int, auth_state) = match data.auth_state_store.lock().unwrap().remove(&body.req_id)
    {
        Some(s) => s,
        None => return HttpResponse::BadRequest().body("Invalid session"),
    };

    let auth_result = match data
        .webauthn
        .finish_passkey_authentication(&body.login_response, &auth_state)
    {
        Ok(res) => res,
        Err(_) => return HttpResponse::Unauthorized().body("Authentication failed"),
    };

    let new_count = auth_result.counter();

    sqlx::query!(
        "UPDATE users SET sign_count = ? WHERE id = ?",
        new_count,
        user_id_int
    )
    .execute(&data.db)
    .await
    .ok();

    HttpResponse::Ok().body("WebAuthn Login Successful")
}

async fn store_cookie(
    data: web::Data<AppState>,
    body: web::Json<CookieRequest>,
) -> impl Responder {
    let (auth_value, expires_at) = (&body.auth_value, &body.expires_at);

    sqlx::query!(
        "INSERT INTO cookies (cookie_value, expires_at) VALUES (?, ?)",
        auth_value,
        expires_at
    )
    .execute(&data.db)
    .await
    .ok();

    HttpResponse::Ok().body("Cookie Stored Successfully")
}

async fn auth(
    data: web::Data<AppState>,
    req: HttpRequest
) -> impl Responder {
    let auth_value = req.headers().get("Cookie").and_then(|h| h.to_str().ok());
    let expires_at = req.headers().get("CookieExpiresAt").and_then(|h| h.to_str().ok());
    let cookie = sqlx::query!(
        "SELECT cookie_value FROM cookies WHERE cookie_value = ? AND expires_at > NOW()",
        auth_value
    )
    .fetch_optional(&data.db)
    .await
    .unwrap_or(None);

    if cookie.is_none() {
        return HttpResponse::Unauthorized().body("Invalid or expired cookie");
    }

    HttpResponse::Ok().body("Authentication Successful")
}