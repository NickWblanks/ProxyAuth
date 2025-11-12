use axum::{Router, routing::get, response::Redirect};
use std::net::SocketAddr;
use anyhow::Result;

pub async fn run_website_server() -> Result<()> {
    // Build router
    let app = Router::new()
        .route("/", get(home))
        .route("/dashboard", get(dashboard));

    // Bind address
    let addr: SocketAddr = "127.0.0.1:8080".parse()?;
    println!("Website server running at http://{}", addr);

    // Run server using axum's built-in Server (no Hyper import needed)
    axum::Server::bind(&addr)
        .serve(app.into_make_service()) // works in Axum 0.7
        .await?;

    Ok(())
}

async fn home() -> &'static str {
    "Welcome to Proto Auth App"
}

async fn dashboard() -> Redirect {
    Redirect::to(
        "https://auth.proto_auth_app.com/login?redirect=https://proto_auth_app.com/dashboard",
    )
}
