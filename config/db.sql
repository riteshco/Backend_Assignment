CREATE DATABASE food_app;
USE food_app;

CREATE TABLE users (
    id integer PRIMARY KEY AUTO_INCREMENT,
    username varchar(100) NOT NULL,
    mobile_number bigint NOT NULL UNIQUE,
    email varchar(100) NOT NULL UNIQUE,
    user_role enum('admin' , 'customer' , 'chef') NOT NULL,
    password_hash varchar(255) NOT NULL,
);

CREATE TABLE Products (
    id integer PRIMARY KEY AUTO_INCREMENT,
    name varchar(100) DEFAULT NULL,
    isavailable boolean DEFAULT true,
    price decimal(10, 2) DEFAULT NULL,
    category varchar(100) DEFAULT NULL,
)

CREATE TABLE Orders (
    id integer PRIMARY KEY AUTO_INCREMENT,
    created_at datetime DEFAULT CURRENT_TIMESTAMP,
    current_status enum('pending', 'accepted', 'rejected', 'delivered') DEFAULT 'pending',
    cutomer_id integer FOREIGN KEY REFERENCES users(id),
    chef_id integer FOREIGN KEY REFERENCES users(id),
    table_number integer DEFAULT NULL,
    instructions text DEFAULT NULL,
);

CREATE TABLE OrderItems(
    id integer PRIMARY KEY AUTO_INCREMENT,
    order_id integer FOREIGN KEY REFERENCES Orders(id),
    product_id integer FOREIGN KEY REFERENCES Products(id),
    quantity integer DEFAULT 1,
);

CREATE TABLE Payments (
    id integer PRIMARY KEY AUTO_INCREMENT,  
    user_id integer FOREIGN KEY REFERENCES users(id),
    order_id integer FOREIGN KEY REFERENCES Orders(id),
    Total_amount decimal(10, 2) NOT NULL,
    payment_status enum('pending', 'completed', 'failed') DEFAULT 'pending',
)
