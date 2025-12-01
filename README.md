# Proxy Auth
This is a project to use WebAuthn to authenticate a user before accessing a dummy website.

## Build Instructions
### Using rustup and NGINX
1. Run `cargo build` in `/Proxy_Authenticator_App`
2. Copy `nginx.conf` to your directory of configuration files for NGINX.
3. Start NGINX

### Using Docker
1. Make sure Docker Desktop is installed and running if you're on Windows.
2. Run `docker compose build` in the root directory.
3. Run `docker compose up` to start the application.
4. Navigate to `localhost:80` to access it.
