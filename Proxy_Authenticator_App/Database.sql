create DATABASE if not exists Proxy_Authenticator_DB;

use Proxy_Authenticator_DB;

CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255),
    email VARCHAR(255),
    credential_id VARCHAR(255),
    public_key TEXT,
    sign_count INT,
    passkey JSON
);
