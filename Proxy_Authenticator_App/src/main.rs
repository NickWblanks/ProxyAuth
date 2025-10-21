use std::fs;
use mysql::*;
use mysql::prelude::*;

fn main() -> Result<()> {
    // Connection URL: replace YOUR_PASSWORD with your MySQL root password
    let url = "mysql://root:Mines1885@localhost:3307"; 

    let pool = Pool::new(url)?;
    let mut conn = pool.get_conn()?;

    // Read the SQL file
    let sql = fs::read_to_string("database.sql")?;
    
    // Execute the SQL (create DB, table, insert)
    conn.query_drop(sql)?;

    // Select all users
    let users: Vec<(i32, String, String, String, String)> = conn.query(
        "SELECT id, username, password, email, passKey FROM Proxy_Authenticator_DB.users"
    )?;

    // Print users
    for (id, username, password, email, passkey) in users {
        println!("ID: {}, Username: {}, Password: {}, Email: {}, PassKey: {}", 
            id, username, password, email, passkey);
    }

    Ok(())
}
