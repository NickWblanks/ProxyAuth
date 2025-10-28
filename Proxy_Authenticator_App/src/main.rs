use mysql::*;
use mysql::prelude::*;
use std::fs;
use std::io::{self, Write};
use rpassword::read_password;

fn main() -> Result<()> {
    // Prompt for username
    print!("Enter username: ");
    io::stdout().flush()?; // make sure the prompt prints before waiting for input
    let mut username = String::new();
    io::stdin().read_line(&mut username)?;
    let username = username.trim();

    // Prompt for password (hidden input)
    print!("Enter password: ");
    io::stdout().flush()?;
    let password = read_password()?; // does not echo input

    // Connection info
    let url = format!("mysql://{}:{}@localhost:3307", username, password);

    // Try connecting to db
    let opts = Opts::from_url(&url)?;
    let pool = Pool::new(opts)?;
    let mut conn = pool.get_conn()?;

    // Read and execute SQL file
    let sql = fs::read_to_string("database.sql")?;
    conn.query_drop(sql)?;

    // Select all users
    let users: Vec<(i32, String, String, String, String)> = conn.query(
        "SELECT id, username, password, email, passKey FROM Proxy_Authenticator_DB.users"
    )?;

    // Print results
    for (id, username, password, email, passkey) in users {
        println!(
            "ID: {}, Username: {}, Password: {}, Email: {}, PassKey: {}",
            id, username, password, email, passkey
        );
    }

    Ok(())
}
