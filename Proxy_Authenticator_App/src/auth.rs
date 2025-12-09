use actix::{get, web};

#[get("/auth")]
pub fn authenticate_header(headers: &HeaderMap) -> HttpResponse {
    let username = headers.get("X-User").and_then(|value| value.to_str().ok().map(|s| s.to_string()));

    match username {
        Some(user) => isUserInDatabase(&user) {
            true => HttpResponse::Ok().header("X-User", user).finish(),
            false => HttpResponse::Unauthorized().finish(),
        }
        None => HttpResponse::Unauthorized().finish(),
    }
}