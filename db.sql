CREATE TABLE roles (
    id SERIAL PRIMARY KEY,
    name VARCHAR(50) UNIQUE NOT NULL
);

CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    role_id INTEGER REFERENCES roles(id) ON DELETE CASCADE,
    username VARCHAR(80) UNIQUE NOT NULL,
    email VARCHAR(80) UNIQUE,
    first_name VARCHAR(80) NOT NULL,
    last_name VARCHAR(80) NOT NULL,
    password VARCHAR(255) NOT NULL
);

INSERT INTO roles (name) VALUES ('admin'), ('customer');
INSERT INTO users (role_id, username, email, first_name, last_name, password) VALUES(1,'admin', 'admin@example.com', 'Admin', 'User', '1234');
INSERT INTO users (role_id, username, email, first_name, last_name, password) VALUES(2,'Vojta', 'vojta@example.com', 'Vojta', 'LastName', '1234');