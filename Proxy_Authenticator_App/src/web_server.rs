use actix_web::{web, App, HttpServer, HttpResponse, Responder};

pub async fn start_web_server() -> std::io::Result<()> {
    let addr = "127.0.0.1:8081"; // matches nginx proxy_pass

    println!("Website running on http://{}", addr);

    HttpServer::new(|| {
        App::new()
            .route("/", web::get().to(index))
            .route("/about", web::get().to(about))
            .route("/dashboard", web::get().to(dashboard))
    })
    .bind(addr)?
    .run()
    .await
}

// Handlers
async fn index() -> impl Responder {
    // This will never directly show login page; Nginx handles auth
    HttpResponse::Ok().body("Welcome to the website! All users must be authenticated first.")
}

async fn about() -> impl Responder {
    HttpResponse::Ok().body("About page of the website.")
}

async fn dashboard() -> impl Responder {
    HttpResponse::Ok().body("Dashboard page — protected, requires auth via Nginx.")
}
