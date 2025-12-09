mod auth;
use actix_files::{Files, NamedFile};
use actix_web::{web, App, HttpResponse, HttpServer, Responder, Result, get, post};
use serde::{Deserialize, Serialize, };
use serde_json::json;
use sqlx::{ MySqlPool, mysql::MySqlPoolOptions};
use base64::{engine::general_purpose, Engine as _};
use url::Url;
use uuid::Uuid;
use sqlx::Row;
use bcrypt::{hash, verify, DEFAULT_COST};
use webauthn_rs::WebauthnBuilder;
use webauthn_rs_core::proto::User as WebAuthnUser;



// -----------------------------------------------------
// STRUCTS
// -----------------------------------------------------

#[derive(Serialize, Deserialize)]
struct DbUser {
    username: String,
    password: String,
    email: String,
    // you can store WebAuthn fields here later
    id: Option<i32>,           // DB id
    credential_id: Option<Vec<u8>>,
    public_key: Option<Vec<u8>>,
    sign_count: Option<i32>,
    passkey: Option<serde_json::Value>,
}


#[derive(Deserialize)]
struct RegisterRequest {
    username: String,
    email: String,
    password: String,
}

#[derive(Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

#[derive(Serialize)]
struct LoginResponse {
    success: bool,
    error: Option<String>,
}

// -----------------------------------------------------
// WebAuthn structs
// -----------------------------------------------------

#[derive(Deserialize)]
struct WebAuthnStartRequest {
    username: String,
    mode: String, // "register" or "login"
}

#[derive(Deserialize)]
struct WebAuthnFinishRequest {
    username: String,
    mode: String, // "register" for now
    credential: CredentialResponse,
}

#[derive(Deserialize)]
struct CredentialResponse {
    id: String,
    rawId: String, // base64url
    type_: String, // "public-key"
    response: CredentialAttestation,
}

#[derive(Deserialize)]
struct CredentialAttestation {
    attestationObject: String, // base64url
    clientDataJSON: String,    // base64url
}
// -----------------------------------------------------
// ROUTES
// -----------------------------------------------------

//get index
//post register user 
//post login user 
//post begin webauthn 
//post end webauthn


#[get("/")]
async fn index() -> Result<NamedFile> {
    Ok(NamedFile::open("Frontend/frontend.html")?)
}

#[get("/frontend")]
async fn frontend() -> Result<NamedFile> {
    Ok(NamedFile::open("Frontend/frontend.html")?)
}

#[post("/register")]
async fn register_user(
    db: web::Data<MySqlPool>,
    req: web::Json<RegisterRequest>,
) -> impl Responder {

    // Hash password
    let hashed = match hash(&req.password, DEFAULT_COST) {
        Ok(h) => h,
        Err(_) => return HttpResponse::InternalServerError().json(
            json!({"error": "Password hashing failed"})
        ),
    };

    // Insert into DB
    let result = sqlx::query!(
        r#"
        INSERT INTO users (username, email, password_hash)
        VALUES (?, ?, ?)
        "#,
        req.username,
        req.email,
        hashed
    )
    .execute(db.get_ref())
    .await;

    // Handle DB errors (duplicate username/email, etc.)
    if let Err(e) = result {
        println!("DB ERROR: {:?}", e);
        return HttpResponse::BadRequest().json(
            json!({"error": "User already exists or DB error"})
        );
    }

    HttpResponse::Ok().json(
        json!({
            "status": "success",
            "username": req.username
        })
    )
}

#[post("/login")]
async fn login_user(
    db: web::Data<sqlx::MySqlPool>,
    req: web::Json<LoginRequest>,
) -> impl Responder {

    // 1. Fetch user row (simple version)
    let row = sqlx::query("SELECT id, password FROM users WHERE username = ?")
        .bind(&req.username)
        .fetch_optional(db.get_ref())
        .await
        .ok()      // DB error -> None
        .flatten(); // Ok(Some(r)) -> Some(r)

    if row.is_none() {
        return HttpResponse::Ok().json(LoginResponse {
            success: false,
            error: Some("Invalid username or password".into()),
        });
    }

    let row = row.unwrap();
    let stored_hash: String = row.get("password");

    // 2. Verify password
    let valid = bcrypt::verify(&req.password, &stored_hash).unwrap_or(false);

    if !valid {
        return HttpResponse::Ok().json(LoginResponse {
            success: false,
            error: Some("Invalid username or password".into()),
        });
    }

    // 3. SUCCESS: return response
    HttpResponse::Ok().json(LoginResponse {
        success: true,
        error: None,
    })
}


#[post("/webauthn/start")]
async fn start_webauthn(
    db: web::Data<MySqlPool>,
    req: web::Json<WebAuthnStartRequest>,
) -> impl Responder {
    println!("WebAuthn START: {} mode={}", req.username, req.mode);

    if req.mode != "register" {
        return HttpResponse::BadRequest().json(json!({"error": "Only registration mode implemented"}));
    }

    // 1. WebAuthn config
    let rp_id = "localhost";
    let rp_origin = Url::parse("http://localhost:8080").expect("Invalid URL");

    let webauthn = WebauthnBuilder::new(rp_id, &rp_origin)
        .expect("Invalid WebAuthn config")
        .build()
        .expect("WebAuthn build failed");

    // 2. Build WebAuthn user
    let user = WebAuthnUser {
        id: req.username.as_bytes().to_vec().into(), // unique user ID (could use DB id instead)
        name: req.username.clone(),
        display_name: req.username.clone(),
    };
    let user_id = Uuid::new_v4();

    // 3. Generate registration challenge
    let (_challenge, registration) = match webauthn.start_passkey_registration(
        user_id,
        "platform",  // authenticator attachment
        "direct",    // attestation type
        None         // extensions
    ) {
        Ok(r) => r,
        Err(e) => {
            println!("WebAuthn error: {:?}", e);
            return HttpResponse::InternalServerError()
                .json(json!({"error": "Failed to start WebAuthn"}));
        }
    };

    // 4. Store registration options in DB as JSON
    let passkey_json = serde_json::to_string(&registration).unwrap();

    let result = sqlx::query!(
        r#"
        UPDATE users
        SET passkey = ?
        WHERE username = ?
        "#,
        passkey_json,
        req.username
    )
    .execute(db.get_ref())
    .await;

    if let Err(e) = result {
        println!("DB ERROR: {:?}", e);
        return HttpResponse::InternalServerError()
            .json(json!({"error": "Failed to store WebAuthn registration state"}));
    }

    // 5. Return registration options to frontend
    HttpResponse::Ok().json(registration)
}

#[post("/webauthn/finish")]
async fn finish_webauthn(
    db: web::Data<MySqlPool>,
    req: web::Json<WebAuthnFinishRequest>,
) -> impl Responder {
    if req.mode != "register" {
        return HttpResponse::BadRequest().json(json!({"error": "Only registration mode implemented"}));
    }

    // 1. Fetch the user and their temporary registration options
    let user_row = sqlx::query!(
        "SELECT id, passkey FROM users WHERE username = ?",
        req.username
    )
    .fetch_one(db.get_ref())
    .await;

    let user_row = match user_row {
        Ok(u) => u,
        Err(_) => return HttpResponse::BadRequest().json(json!({"error": "User not found"})),
    };

    let passkey_json: String = match user_row.passkey {
        Some(ref p) => p.clone(),
        None => return HttpResponse::BadRequest().json(json!({"error": "No WebAuthn registration started"})),
    };

    // 2. Deserialize the stored registration options
    let registration: PasskeyRegistration = serde_json::from_str(&passkey_json).unwrap();

    // 3. Build WebAuthn config again (same as start)
    let rp_id = "localhost";
    let rp_origin = Url::parse("http://localhost:8080").expect("Invalid URL");

    let webauthn = WebauthnBuilder::new(rp_id, &rp_origin)
        .expect("Invalid WebAuthn config")
        .build()
        .expect("WebAuthn build failed");

    // 4. Prepare the attestation data from frontend
    use base64_url::decode;

    let attestation_object = decode(&req.credential.response.attestationObject).unwrap();
    let client_data_json = decode(&req.credential.response.clientDataJSON).unwrap();
    let raw_id = decode(&req.credential.rawId).unwrap();

    // 5. Verify the attestation
    let result = webauthn.finish_passkey_registration(
        &registration,
        &attestation_object,
        &client_data_json,
        &raw_id,
    );

    let cred = match result {
        Ok(c) => c,
        Err(e) => {
            println!("WebAuthn finish error: {:?}", e);
            return HttpResponse::InternalServerError().json(json!({"error": "WebAuthn verification failed"}));
        }
    };

    // 6. Store credential info in DB
    let result = sqlx::query!(
        r#"
        UPDATE users
        SET credential_id = ?, public_key = ?, sign_count = ?, passkey = NULL
        WHERE username = ?
        "#,
        cred.cred_id,
        cred.public_key,
        cred.sign_count as i32,
        req.username
    )
    .execute(db.get_ref())
    .await;

    if let Err(e) = result {
        println!("DB ERROR: {:?}", e);
        return HttpResponse::InternalServerError().json(json!({"error": "Failed to store credential"}));
    }

    HttpResponse::Ok().json(json!({"status": "success"}))
}

//main
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new()
            .service(index)
            .service(frontend)
            .service(register_user)
            .service(login_user)
            .service(start_webauthn)
            .service(end_webauthn)
            .service(auth::authenticate_header)
            .service(finish_webauthn)
            .service(Files::new("/", "Frontend/"))
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}