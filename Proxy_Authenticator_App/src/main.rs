use tokio::task;

mod Auth_Server;
mod Website_Server;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Spawn the Auth server
    let auth_task = task::spawn(async {
        Auth_Server::run_auth_server().await
    });

    // Spawn the Website server
    let web_task = task::spawn(async {
        Website_Server::run_website_server().await
    });

    // Run both servers concurrently
    let (auth_res, web_res) = tokio::try_join!(auth_task, web_task)?;

    // Propagate errors if any
    auth_res?;
    web_res?;

    Ok(())
}
