import express from 'express';
import { runDBCommand } from '../app.js';
import dotenv from 'dotenv';
dotenv.config();
import { authenticateToken } from '../utils/helpers.js';

const router = express.Router();

router.post('/add-to-cart/:id', authenticateToken, async (req, res) => {
    try {
        const productID = req.params.id;
        const quantity = req.body.quantity;
        const customerID = req.user.id;
        const query = 'INSERT INTO OrderItems (customer_id , product_id , quantity) VALUES (? , ? , ?)';
        await runDBCommand(query, [customerID, productID, quantity]);
        res.redirect('/cart');
    }
    catch (error) {
        res.status(500);
        error.status = 500;
        error.message = 'Error in adding to cart';
        console.error('Error in adding to cart:', error);
        res.render('error.ejs', { error });
    }
});

router.post('/add-one-to-cart/:id', authenticateToken, async (req, res) => {
    try {
        const productID = req.params.id;
        const customerID = req.user.id;
        const query = 'INSERT INTO OrderItems (customer_id , product_id) VALUES (? , ?)';
        await runDBCommand(query, [customerID, productID]);
        res.redirect('/cart');
    }
    catch (error) {
        res.status(500);
        error.status = 500;
        error.message = 'Error in adding to cart';
        console.error('Error in adding to cart:', error);
        res.render('error.ejs', { error });
    }
});

router.post('/remove-from-cart/:id', authenticateToken, async (req, res) => {
    try {
        const productID = req.params.id;
        const customerID = req.user.id;
        const query = 'DELETE FROM OrderItems WHERE customer_id = ? AND id = ?';
        await runDBCommand(query, [customerID, productID]);
        res.redirect('/cart');
    }
    catch (error) {
        res.status(500);
        error.status = 500;
        error.message = 'Error in removing from cart';
        console.error('Error in removing from cart:', error);
        res.render('error.ejs', { error });
    }
});

router.get('/cart', authenticateToken, async (req, res) => {
    const msg = req.session.message;
    req.session.message = null;
    try {
        const query = 'SELECT * FROM OrderItems WHERE customer_id = ? AND order_id IS NULL';
        const orderedItems = await runDBCommand(query, [req.user.id]);
        const query2 = 'SELECT id , product_name FROM Products WHERE id IN (SELECT product_id FROM OrderItems WHERE customer_id = ? AND order_id IS NULL)'
        const products = await runDBCommand(query2, [req.user.id]);
        res.render('cart.ejs', { orderedItems, products, msg  , user: req.user });
    }
    catch (error) {
        res.status(500);
        error.status = 500;
        error.message = 'Error in fetching cart items';
        console.error('Error in fetching cart items:', error);
        res.render('error.ejs', { error });
    }
});

router.post('/api/cart/order', authenticateToken, async (req, res) => {
    const { table_number, instructions } = req.body;
    if (!table_number) {
        res.status(401).send("Must give table number!")
    }
    try {
        const query = 'SELECT * FROM OrderItems WHERE customer_id = ? AND order_id IS NULL'
        const cartItems = await runDBCommand(query, [req.user.id]);

        const query2 = 'INSERT INTO Orders (customer_id , table_number , instructions) VALUES ( ? , ? , ?)';
        const result = await runDBCommand(query2, [req.user.id, table_number, instructions]);

        const query3 = 'UPDATE OrderItems SET order_id = ? WHERE customer_id = ? AND order_id IS NULL';
        await runDBCommand(query3, [result.insertId, req.user.id])
        const prices = await runDBCommand(`
            SELECT Products.price 
            FROM OrderItems 
            JOIN Products ON OrderItems.product_id = Products.id 
            WHERE OrderItems.order_id = ?
            `, [result.insertId]);
        let totalAmount = 0;
        for (let i = 0; i < cartItems.length; i++) {
            const productPrice = prices[i].price;
            const quantity = cartItems[i].quantity;
            totalAmount += productPrice * quantity;
        }
        const query4 = 'INSERT INTO Payments (user_id , order_id , Total_amount) VALUES (?,?,?)';
        await runDBCommand(query4, [req.user.id, result.insertId, totalAmount]);
        console.log('Order placed successfully:', result.insertId);
        req.session.message = "Order placed successfully!";
        res.redirect('/home');
    }
    catch (error) {
        res.status(500);
        error.status = 500;
        error.message = 'Error in ordering';
        console.error('Error in ordering: ', error);
        res.render('error.ejs', { error });
    }
});

export default router;