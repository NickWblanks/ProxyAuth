use sqlx::{Connection, ConnectOptions};
use sqlx::mysql::{MySqlConnectOptions, MySqlConnection, MySqlPool, MySqlSslMode};

let conn = MySqlConnectOptions::new()
    .host("localhost")
    .username("root")
    .password("examplepassword")
    .database("Proxy_Authenticator_DB")
    .connect().await?;

let pool = MySqlPool::connect_with(conn).await?;

pub fn isUserInDatabase(username: &str) -> bool {
    sqlx::query("SELECT COUNT(*) as count FROM users WHERE username = ?")
        .bind(username)
        .fetch_one(&pool)
        .await
        .map(|row| {
            let count: i64 = row.get("count");
            count > 0
        })
}