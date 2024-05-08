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
    password VARCHAR(255) NOT NULL,
    profile_picture VARCHAR(255)
);

INSERT INTO roles (name) VALUES ('admin'), ('customer');
--CompleteOmissionOfHashFunction-3 - START
--CompleteOmissionOfHashFunction-3 - END
--WeakHashFunction-3 - START
--WeakHashFunction-3 - END
--WeakHashFunctionWithSalt-3 - START
--Status: Fixed
--Description: CWE-327: Use of a Broken or Risky Cryptographic Algorithm -> https://cwe.mitre.org/data/definitions/327.html
INSERT INTO users (role_id, username, email, first_name, last_name, password) VALUES(1,'admin', 'admin@example.com', 'John', 'Doe', '$argon2id$v=19$m=65536,t=3,p=4$L3jNUzeRVWWiYP/u/mt2Ag$QYqf5Ayvr3H+XtD7QdOMh92Hf456DTpjmfzUq96lZgE');
--WeakHashFunctionWithSalt-3 - END

CREATE TABLE products (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) UNIQUE NOT NULL,
    stock INTEGER NOT NULL,
    price FLOAT NOT NULL,
    image VARCHAR(255) NOT NULL,
    details JSONB
);

INSERT INTO products (name, stock, price, image, details) VALUES
    ('Cappuccino', 100, 7.99, 'images/products/coffee/coffee1.svg', '{"Coffee": "1 shot", "Milk": "Semi-Skimmed"}'),
    ('Flat White', 100, 9.99, 'images/products/coffee/coffee2.svg', '{"Coffee": "2 shots", "Milk":"Semi-Skimmed"}'),
    ('Caramel Latte', 100, 6.99, 'images/products/coffee/coffee3.svg', '{"Coffee": "1 shot", "Milk": "Semi-Skimmed"}'),
    ('Pistachio Latte', 100, 5.99, 'images/products/coffee/coffee4.svg', '{"Coffee": "1 shot", "Milk": "Regular Foam"}'),
    ('Macchiato', 100, 9.99, 'images/products/coffee/coffee5.svg', '{"Coffee": "1 shot", "Milk": "Regular Foam"}'),
    ('Caffé Mocha', 100, 4.99, 'images/products/coffee/coffee6.svg', '{"Coffee": "2 shots", "Milk": "Regular Foam"}'),
    ('Matcha Latte', 100, 2.99, 'images/products/coffee/coffee7.svg', '{"Coffee": "2 shots", "Milk": "Semi-Skimmed"}'),
    ('Caturra', 100, 82.99, 'images/products/coffee/coffee8.svg', '{"Weight": "1000mg"}'),
    ('Castillo', 18, 92.99, 'images/products/coffee/coffee8.svg', '{"Weight": "1000mg"}'),
    ('Bourbon', 18, 122.99, 'images/products/coffee/coffee8.svg', '{"Weight": "1000mg"}'),
    ('Catimor', 18, 75.99, 'images/products/coffee/coffee8.svg', '{"Weight": "1000mg"}'),
    --Teas
    ('Green Tea', 18, 75.99, 'images/products/tea/tea1.svg', '{"Caffeine": "30-50 mg"}'),
    ('Yellow Tea', 18, 75.99, 'images/products/tea/tea2.svg', '{"Caffeine": "18-47 mg"}'),
    ('Earl Grey', 18, 75.99, 'images/products/tea/tea3.svg', '{"Caffeine": "22-58 mg"}'),
    ('Ginger Tea', 18, 75.99, 'images/products/tea/tea5.svg', '{"Caffeine": "0 mg"}'),
    ('Green Tea (Loose leaf)', 18, 75.99, 'images/products/tea/tea6.svg', '{"Caffeine": "30-50 mg"}'),
    ('Yellow Tea (Loose leaf)', 18, 75.99, 'images/products/tea/tea6.svg', '{"Caffeine": "30-50 mg"}'),
    ('Earl Grey (Loose leaf)', 18, 75.99, 'images/products/tea/tea6.svg', '{"Caffeine": "30-50 mg"}');
    
INSERT INTO products (name, stock, price, image) VALUES
    --Accessories
    ('Coffee Brew', 18, 75.99, 'images/products/accessories/accessory1.svg'),
    ('Coffee Portafilter', 18, 75.99, 'images/products/accessories/accessory2.svg'),
    ('Coffee Machine', 18, 75.99, 'images/products/accessories/accessory3.svg'),
    ('Tea Pot', 18, 75.99, 'images/products/accessories/accessory4.svg'),
    ('Mug', 18, 75.99,'images/products/accessories/accessory5.svg'),
    ('Coffee Cup', 18, 75.99, 'images/products/accessories/accessory6.svg');

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
    (19,3),
    (20,3),
    (21,3),
    (22,3),
    (23,3),
    (24,3);


CREATE TABLE orders (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    total_price FLOAT NOT NULL,
    date TIMESTAMP NOT NULL
);


CREATE TABLE order_items (
    id SERIAL PRIMARY KEY,
    product_id INTEGER REFERENCES products(id) ON DELETE CASCADE,
    order_id INTEGER REFERENCES orders(id) ON DELETE CASCADE,
    quantity INTEGER NOT NULL,
    total FLOAT NOT NULL
);