CREATE DATABASE IF NOT EXISTS Proxy_Authenticator_DB;
USE Proxy_Authenticator_DB;

CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,

    username VARCHAR(255) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,

    -- If user uses password login
    password_hash VARCHAR(255),

    -- WebAuthn primary credential info
    credential_id VARBINARY(255),      -- MUST be binary, not text
    public_key VARBINARY(1024),        -- COSE public key bytes
    sign_count INT DEFAULT 0,          -- WebAuthn counter

    -- Store any extra WebAuthn stuff like transports, attestation, etc
    passkey JSON,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
