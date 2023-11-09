CREATE TABLE roles (
    id SERIAL PRIMARY KEY,
    name VARCHAR(50) UNIQUE NOT NULL
);

INSERT INTO roles (name) VALUES ('admin'), ('customer');

CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(80) UNIQUE NOT NULL,
    first_name VARCHAR(80) NOT NULL,
    last_name VARCHAR(80) NOT NULL,
    password VARCHAR(255) NOT NULL,
    salt VARCHAR(80)
);


CREATE TABLE user_roles (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    role_id INTEGER REFERENCES roles(id) ON DELETE CASCADE
);


INSERT INTO users (username, first_name, last_name, password, salt)
VALUES
    ('admin', 'James', 'McDonald', 'admin_password_hash', NULL),
    ('anndoe', 'Anne', 'Doe', 'customer_password_hash1', NULL),
    ('Bob', 'Bob', 'Clever', 'customer_password_hash2', NULL);


INSERT INTO user_roles (user_id, role_id)
VALUES
    (1, 1), 
    (2, 2),
    (3, 2); 
