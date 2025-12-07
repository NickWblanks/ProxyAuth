mod auth;
use actix_files::{Files, NamedFile};
use actix_web::{web, App, HttpResponse, HttpServer, Responder, Result, get, post};
use serde::{Deserialize, Serialize};
use sqlx::{ MySqlPool, mysql::MySqlPoolOptions};
use base64::{engine::general_purpose, Engine as _};
use uuid::Uuid;

// -----------------------------------------------------
// STRUCTS
// -----------------------------------------------------

#[derive(Serialize, Deserialize)]
struct User {
    username: String,
    password: String,
    email: String
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
async fn register_user() -> impl Responder {
    HttpResponse::Ok().body("register user")
}

#[post("/login")]
async fn login_user() -> impl Responder {
    HttpResponse::Ok().body("login user")
}

#[post("/webauthn/start")]
async fn start_webauthn() -> impl Responder {
    HttpResponse::Ok().body("start webauthn")
}

#[post("/webauthn/end")]
async fn end_webauthn() -> impl Responder {
    HttpResponse::Ok().body("end webauthn")
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
            .service(Files::new("/", "Frontend/"))
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}