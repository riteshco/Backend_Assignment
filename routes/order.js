import express from 'express';
import { runDBCommand } from '../app.js';
import dotenv from 'dotenv';
dotenv.config();
import { authenticateToken } from '../utils/helpers.js';

const router = express.Router();

router.get('/orders', authenticateToken, async (req, res) => {
    try {
        const query1 = 'SELECT * FROM Users WHERE email = ?';
        const customer = await runDBCommand(query1, [req.user.email]);

        const query2 = 'SELECT * FROM Orders WHERE customer_id = ?';
        const orders = await runDBCommand(query2, [customer[0].id])

        const query3 = `
            SELECT p.product_name
            FROM Orders o
            JOIN OrderItems oi ON o.id = oi.order_id
            JOIN Products p ON oi.product_id = p.id
            WHERE o.customer_id = ?;
        `;

        const productRows = await runDBCommand(query3, [customer[0].id]);
        const productNames = productRows.map(row => row.product_name);

        const query4 = 'SELECT p.payment_status FROM Payments p JOIN Orders o ON p.order_id = o.id WHERE o.customer_id = ?';
        const paymentStatusRows = await runDBCommand(query4, [customer[0].id]);
        res.render('orders.ejs', { orders, productNames, paymentStatusRows , user: req.user });

    } catch (error) {
        res.status(500);
        err.status = 500;
        err.message = 'Error fetching orders';
        console.error('Error fetching orders:', err);
        res.render('error.ejs', { error });
    }
});

router.post('/api/order-done/:id', async (req, res) => {
    try {
        const query = 'UPDATE Orders SET current_status = "delivered" WHERE id = ?';
        await runDBCommand(query, [req.params.id]);
        res.redirect('/home');
    }
    catch (error) {
        res.status(500);
        error.status = 500;
        error.message = 'Error in marking order as done';
        console.error('Error in marking order as done:', error);
        res.render('error.ejs', { error });
    }
});

router.get('/past-orders', authenticateToken, async (req, res) => {
    try {
        const query = 'SELECT * FROM Orders WHERE customer_id = ? AND current_status = "delivered"';
        const orders = await runDBCommand(query, [req.user.id]);
        const query2 = 'SELECT * FROM Payments WHERE user_id = ? AND payment_status = "completed" AND order_id IN (SELECT id FROM Orders WHERE customer_id = ? AND current_status = "delivered")';
        const payments = await runDBCommand(query2, [req.user.id , req.user.id]);
        res.render('past-orders.ejs', { orders , payments , user: req.user });
    }
    catch (error) {
        res.status(500);
        error.status = 500;
        error.message = 'Error in fetching payments';
        console.error('Error in fetching payments:', error);
        res.render('error.ejs', { error });
    }
});

router.get('/all-orders', authenticateToken, async (req, res) => {
    if (req.user.user_role === "admin") {
        try {
            const orders = await runDBCommand('SELECT * FROM Orders');
            res.render('all_orders.ejs', { orders , user: req.user });
        }
        catch (err) {
            res.status(500);
            err.status = 500;
            err.message = 'Error in fetching orders';
            console.error('Error in fetching orders:', err);
            res.render('error.ejs', { error: err });
        }
    }
    else {
        res.status(401).send("Forbidden Access")
    }
});

router.post('/api/delete-order/:id', authenticateToken, async (req, res) => {
    let id = -1;
    try {

        if (req.user.user_role === "admin") {
            id = req.params.id;
            const query = 'DELETE FROM Orders WHERE id = ?';
            await runDBCommand(query, id);
            res.redirect('/all-orders');
        }
        if (req.user.user_role === "customer") {
            const orders = await runDBCommand('SELECT id FROM Orders WHERE customer_id = ?', req.user.id);
            if (orders.some(order => order.id == req.params.id)) {
                id = req.params.id;
                const query = 'DELETE FROM Orders WHERE id = ?';
                await runDBCommand(query, id)
                res.redirect('/orders')
            }
            else {
                res.status(401).send("User not allowed for this order!")
            }
        }
    }
    catch (error) {
        res.status(500);
        error.status = 500;
        error.message = 'Error in deleting order';
        console.error('Error in deleting order:', error);
        res.render('error.ejs', { error });
    }
});

router.get('/order/items/:id', authenticateToken, async (req, res) => {
    try {
        const orderItems = await runDBCommand('SELECT * FROM OrderItems WHERE order_id = ?', [req.params.id]);
        const products = await runDBCommand('SELECT * FROM Products WHERE id IN (SELECT product_id FROM OrderItems WHERE order_id = ?)', [req.params.id]);
        res.render('order_items.ejs', { orderId: req.params.id, orderItems, products , user: req.user });
    }
    catch (error) {
        res.status(500);
        error.status = 500;
        error.message = 'Error in fetching order items';
        console.error('Error in fetching order items:', error);
        res.render('error.ejs', { error });
    }
});

router.get('/order/payment/:id', authenticateToken, async (req, res) => {
    try {
        const payment = await runDBCommand('SELECT * FROM Payments WHERE order_id = ?', [req.params.id]);
        if (payment.length === 0) {
            res.status(404);
            const error = new Error('Payment not found for this order');
            error.status = 404;
            error.message = 'No payment found for the specified order ID';
            console.error('Payment not found:', error.message);
            return res.render('error.ejs', { error });
        } else {
            res.render('order_payment.ejs', { orderId: req.params.id, payment: payment[0] , user:req.user });
        }
    }
    catch (error) {
        res.status(500);
        error.status = 500;
        error.message = 'Error in fetching order payment';
        console.error('Error in fetching order payment:', error);
        res.render('error.ejs', { error });
    }
}
);

router.get('/order/bill/:id', authenticateToken, async (req, res) => {
    try {
        const payment = await runDBCommand('SELECT * FROM Payments WHERE order_id = ?', [req.params.id]);
        if (payment.length === 0) {
            res.status(404);
            const error = new Error('Bill not found for this order');
            error.status = 404;
            error.message = 'No bill found for the specified order ID';
            console.error('Bill not found:', error.message);
            return res.render('error.ejs', { error });
        } else {
            res.render('order_bill.ejs', { orderId: req.params.id, payment: payment[0] , user: req.user });
        }
    }
    catch (error) {
        res.status(500);
        error.status = 500;
        error.message = 'Error in fetching order payment';
        console.error('Error in fetching order payment:', error);
        res.render('error.ejs', { error });
    }
}); 

export default router;