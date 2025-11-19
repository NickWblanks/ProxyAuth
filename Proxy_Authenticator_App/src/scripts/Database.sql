create DATABASE if not exists Proxy_Authenticator_DB;

use Proxy_Authenticator_DB;

CREATE TABLE IF NOT EXISTS `Proxy_Authenticator_DB`.`users` (
    `id` INT PRIMARY KEY NOT NULL AUTO_INCREMENT,
    `username` VARCHAR(45) NOT NULL,
    `password` VARCHAR(45) NOT NULL,
    `email` VARCHAR(45) NOT NULL,
    `public_key` VARCHAR(45) NOT NULL
);

INSERT into users (username, password, email, public_key) VALUES ("admin", "admin", "admin", "admin");
