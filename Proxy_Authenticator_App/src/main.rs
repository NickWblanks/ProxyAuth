mod Auth_Server;
mod web_server;

fn main() -> std::io::Result<()> {
    // Create an Actix system
    let system = actix_web::rt::System::new();

    // Run both servers on this system
    system.block_on(async {
        let auth_server = actix_web::rt::spawn(Auth_Server::start_auth_server());
        let web_server = actix_web::rt::spawn(web_server::start_web_server());

        // Wait for both servers (they run forever)
        let _ = futures::join!(auth_server, web_server);
    });

    Ok(())
}
