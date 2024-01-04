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


CREATE TABLE products (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) UNIQUE NOT NULL,
    stock INTEGER NOT NULL,
    price FLOAT NOT NULL,
    description VARCHAR(255) NOT NULL,
    image VARCHAR(255) NOT NULL,
    includes VARCHAR(255)[]
);

INSERT INTO products (name, stock, price, description, image, includes) VALUES
    ('Cappuccino', 100, 7.99, 'Description for Product 1', 'images/products/coffee/coffee1.svg', ARRAY['Coffee: 1 shot', 'Milk: Semi-Skimmed']),
    ('Flat White', 100, 9.99, 'Description for Product 2', 'images/products/coffee/coffee2.svg', ARRAY['Coffee: 2 shots', 'Milk:Semi-Skimmed']),
    ('Caramel Latte', 100, 6.99, 'Description for Product 3', 'images/products/coffee/coffee3.svg', ARRAY['Coffee: 1 shot', 'Milk: Semi-Skimmed']),
    ('Pistachio Latte', 100, 5.99, 'Description for Product 4', 'images/products/coffee/coffee4.svg', ARRAY['Coffee: 1 shot', 'Milk: Regular Foam']),
    ('Macchiato', 100, 9.99, 'Description for Product 5', 'images/products/coffee/coffee5.svg', ARRAY['Coffee: 1 shot', 'Milk: Regular Foam']),
    ('Caffé Mocha', 100, 4.99, 'Description for Product 6', 'images/products/coffee/coffee6.svg', ARRAY['Coffee: 2 shots', 'Milk: Regular Foam']),
    ('Matcha Latte', 100, 2.99, 'Description for Product 7', 'images/products/coffee/coffee7.svg', ARRAY['Coffee: 2 shots', 'Milk: Semi-Skimmed']),
    ('Caturra', 100, 82.99, 'Description for Product 8', 'images/products/coffee/coffee8.svg', ARRAY['Coffee: None','Milk: None','Weight: 1000mg']),
    ('Castillo', 18, 92.99, 'Description for Product 9', 'images/products/coffee/coffee8.svg', ARRAY['Coffee: None','Milk: None','Weight: 1000mg']),
    ('Bourbon', 18, 122.99, 'Description for Product 10', 'images/products/coffee/coffee8.svg', ARRAY['Coffee: None','Milk: None','Weight: 1000mg']),
    ('Catimor', 18, 75.99, 'Description for Product 11', 'images/products/coffee/coffee8.svg', ARRAY['Coffee: None','Milk: None','Weight: 1000mg']),
    --Teas
    ('Green Tea', 18, 75.99, 'Description for Product 12', 'images/products/coffee/coffee8.svg', ARRAY['Coffee: None','Milk: None','Weight: None', 'Caffeine: 30-50 mg']),
    ('Yellow Tea', 18, 75.99, 'Description for Product 13', 'images/products/coffee/coffee8.svg', ARRAY['Coffee: None','Milk: None','Weight: None', 'Caffeine: 18-47 mg']),
    ('Earl Grey', 18, 75.99, 'Description for Product 14', 'images/products/coffee/coffee8.svg', ARRAY['Coffee: None','Milk: None','Weight: None', 'Caffeine: 22-58 mg']),
    ('Matcha', 18, 75.99, 'Description for Product 15', 'images/products/coffee/coffee8.svg', ARRAY['Coffee: None','Milk: None','Weight: None', 'Caffeine: ~126 mg']),
    ('Green Tea (Loose leaf)', 18, 75.99, 'Description for Product 16', 'images/products/coffee/coffee8.svg', ARRAY['Coffee: None','Milk: None','Weight: 1000mg', 'Caffeine: 30-50 mg']),
    ('Yellow Tea (Loose leaf)', 18, 75.99, 'Description for Product 17', 'images/products/coffee/coffee8.svg', ARRAY['Coffee: None','Milk: None','Weight: 1000mg', 'Caffeine: 30-50 mg']),
    ('Earl Grey (Loose leaf)', 18, 75.99, 'Description for Product 18', 'images/products/coffee/coffee8.svg', ARRAY['Coffee: None','Milk: None','Weight: 1000mg', 'Caffeine: 30-50 mg']),
    ('Matcha (Loose leaf)', 18, 75.99, 'Description for Product 19', 'images/products/coffee/coffee8.svg', ARRAY['Coffee: None','Milk: None','Weight: 1000mg', 'Caffeine: 30-50 mg']);

CREATE TABLE categories (
    id SERIAL PRIMARY KEY,
    name VARCHAR(50) UNIQUE NOT NULL
);

INSERT INTO categories (name) VALUES ('coffee'), ('tea'), ('accessories');

CREATE TABLE product_categories (
    id SERIAL PRIMARY KEY,
    product_id INTEGER REFERENCES products(id) ON DELETE CASCADE,
    category_id INTEGER REFERENCES categories(id) ON DELETE CASCADE
);  

INSERT INTO product_categories (product_id, category_id) VALUES 
    (1,1),
    (2,1),
    (3,1),
    (4,1),
    (5,1),
    (6,1),
    (7,1),
    (8,1),
    (9,1),
    (10,1),
    (11,1),
    (12,2),
    (13,2),
    (14,2),
    (15,2),
    (16,2),
    (17,2),
    (18,2),
    (19,2);
