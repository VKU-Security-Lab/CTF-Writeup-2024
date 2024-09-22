CREATE DATABASE challenge;
USE challenge;

CREATE TABLE flags (
    flag TEXT
);
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(256),
    password VARCHAR(256),
    salt VARCHAR(32),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO flags (flag) VALUES ('FLAG_REDACTED_GO_GET_THE_REAL_ONE');

-- Check if the user exists before creating
DROP USER IF EXISTS 'user'@'%';
CREATE USER 'user'@'%' IDENTIFIED BY 'password';
GRANT SELECT, INSERT ON challenge.users TO 'user'@'%';
GRANT SELECT ON challenge.flags TO 'user'@'%';
FLUSH PRIVILEGES;
