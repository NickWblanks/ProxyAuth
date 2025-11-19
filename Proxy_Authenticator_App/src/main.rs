use mysql::*;
use mysql::prelude::*;
use std::fs;
use std::io::{self, Write};
use rpassword::read_password;
use dotenv::dotenv;
use std::env;

fn main() -> Result<PooledConn> {
    // Connection info
    dotenv().ok();
    let username = env::var("MYSQL_USERNAME")
    let password = env::var("MYSQL_PASSWORD")
    let hostname = env::var("MYSQL_HOSTNAME")
    let port = env::var("MYSQL_PORT")
    let url = format!("mysql://{}:{}@{}:{}", username, password, hostname, port);

    // Try connecting to db
    let opts = Opts::from_url(&url)?;
    let pool = Pool::new(opts)?;
    let mut conn = pool.get_conn()?;

    // Read and execute SQL file
    let sql = fs::read_to_string("database.sql")?;
    conn.query_drop(sql)?;

    Ok(())
}
