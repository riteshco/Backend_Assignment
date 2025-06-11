CREATE DATABASE food_app;
USE food_app;

CREATE TABLE Users (
    id integer PRIMARY KEY AUTO_INCREMENT,
    username varchar(100) NOT NULL,
    mobile_number bigint NOT NULL UNIQUE,
    email varchar(100) NOT NULL UNIQUE,
    user_role enum('admin' , 'customer' , 'chef') NOT NULL,
    password_hash varchar(255) NOT NULL
);          

CREATE TABLE Products ( 
    id integer PRIMARY KEY AUTO_INCREMENT,
    product_name varchar(100) NOT NULL UNIQUE, 
    isavailable boolean DEFAULT true,
    price decimal(10, 2) NOT NULL,
    category varchar(100) DEFAULT NULL,
    image_url varchar(255) DEFAULT NULL
);

CREATE TABLE Orders (
    id integer PRIMARY KEY AUTO_INCREMENT,
    created_at datetime DEFAULT CURRENT_TIMESTAMP,
    current_status enum('pending', 'accepted', 'rejected', 'delivered') DEFAULT 'pending',
    customer_id integer,
    chef_id integer DEFAULT NULL,
    table_number integer NOT NULL,
    instructions text DEFAULT NULL,
    FOREIGN KEY (customer_id) REFERENCES Users(id) ON DELETE CASCADE,
    FOREIGN KEY (chef_id) REFERENCES Users(id) ON DELETE SET NULL
);  
    
CREATE TABLE OrderItems(
    id integer PRIMARY KEY AUTO_INCREMENT,
    order_id integer,
    product_id integer,
    quantity integer DEFAULT 1,
    FOREIGN KEY (order_id) REFERENCES Orders(id) ON DELETE CASCADE,
    FOREIGN KEY (product_id) REFERENCES Products(id) ON DELETE CASCADE   
);      

CREATE TABLE Payments (
    id integer PRIMARY KEY AUTO_INCREMENT,  
    user_id integer,        
    order_id integer,
    Total_amount decimal(10, 2) NOT NULL,
    payment_status enum('pending', 'completed', 'failed') DEFAULT 'pending',
    FOREIGN KEY (user_id) REFERENCES Users(id) ON DELETE CASCADE,
    FOREIGN KEY (order_id) REFERENCES Orders(id) ON DELETE CASCADE
);  

-- demo products
INSERT INTO Products (product_name , price , category , image_url) VALUES ('Pizza' , 399 , 'Fast Food' , '/demo_products/pizza.jpg');
INSERT INTO Products (product_name , price , category , image_url) VALUES ('Burger' , 129 , 'Fast Food' , '/demo_products/burger.jpg');