import express from 'express';
import db from './config/database.js';
import path from 'path';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';
import cookieParser from 'cookie-parser';
dotenv.config();
import { hashPswd, verifyPswd, generateToken, authenticateToken } from './utils/helpers.js';
import jwt from 'jsonwebtoken';
import { query, validationResult } from 'express-validator';
import session from 'express-session';

const port = 8080;

const app = express();

app.use(session({
    secret: process.env.JWT_SECRET,
    resave: false,
    saveUninitialized: true,
}));

app.set('view engine', 'ejs');

app.use(cookieParser());
app.use(express.urlencoded());
app.use(express.json());

app.use((req, res, next) => {
  if (req.headers.accept && req.headers.accept.includes('text/html')) {
    const cleanPath = req.path.split('/')[1];
    res.locals.currentPage = cleanPath;
}
  res.locals.user = req.user;
  next();
});

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
app.use(express.static(path.join(__dirname, 'public')));


const runDBCommand = async (query, params = []) => {
    try {
        const [rows] = await db.query(query, params);
        return rows;
    } catch (err) {
        throw err;
    }
};

app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
}
);

app.get('/', (req, res) => {
    if (req.cookies.token) {
        try {
            const user = jwt.verify(req.cookies.token, process.env.JWT_SECRET);
            if (user.user_role === 'customer' || user.user_role === 'chef') {
                return res.redirect('/home');
            }
            else if (user.user_role === 'admin') {
                return res.redirect('/admin');
            }
        }
        catch (error) {
            console.error('Invalid token:', error.message);
            res.send('Invalid Token!')
        }
    }
    res.render('index.ejs');
})

app.get('/login', (req, res) => {
    const error = req.session.message;
    req.session.message = null;
    if (req.cookies.token) {
        try {
            const user = jwt.verify(req.cookies.token, process.env.JWT_SECRET);
            if (user.user_role === 'customer' || user.user_role === 'chef') {
                return res.redirect('/home');
            }
            else if (user.user_role === 'admin') {
                return res.redirect('/admin');
            }
        }
        catch (error) {
            console.error('Invalid token:', error.message);
            res.send('Invalid Token!')
        }
    }
    res.render('login.ejs', { error });
});

app.get('/signup', (req, res) => {
    const error = req.session.message;
    req.session.message = null;
    if (req.cookies.token) {
        if (req.user) {
            if (req.user.user_role === 'customer' || req.user.user_role === 'chef') {
                return res.redirect('/home');
            }
            else if (req.user.user_role === 'admin') {
                return res.redirect('/admin');
            }
        }
    }
    res.render('signup.ejs', { error });
}
);

app.post('/api/logout', (req, res) => {
    res.clearCookie('token');
    res.redirect('/');
}
);

app.post('/register', async (req, res) => {
    const { username, mobile_number, email, password } = req.body;
    if (!username || !mobile_number || !email || !password) {
        return res.status(400).json({ error: 'All fields are required' });
    }
    if (username.toLowerCase() === "admin") {
        req.session.message = "Forbidden Username!";
        return res.redirect('/signup');
    }
    if (mobile_number.length != 10) {
        req.session.message = "Invalid Mobile Number!";
        return res.redirect('/signup');
    }
    if (password.length < 8) {
        return res.status(400).send('Password Length should be greater than equal to 8')
    }
    try {
        const hshPswd = await hashPswd(password);
        const query = 'INSERT INTO Users (username, mobile_number, email, user_role, password_hash) VALUES (?,?,?,"customer",?)'
        const params = [username, mobile_number, email, hshPswd];
        await runDBCommand(query, params);
        res.redirect('/login');
    }
    catch (error) {
        console.error('Error during registration: ', error);
        if (error.code === 'ER_DUP_ENTRY') {
            req.session.message = "User already exists!";
            return res.redirect('/signup');
        }
        res.status(500);
        error.status = 500;
        error.message = 'Error in registering';
        console.error('Error in registering:', error);
        res.render('error.ejs', { error });
    }
});

app.post('/api/register', query(), async (req, res) => {
    const { username, mobile_number, email, password } = req.body;
    if (!username || !mobile_number || !email || !password) {
        return res.status(400).json({ error: 'All fields are required' });
    }
    if (mobile_number.length != 10) {
        return res.status(400).json({ error: 'Invalid mobile number' })
    }
    if (password.length < 8) {
        return res.status(400).send('Password Length should be greater than equal to 8')
    }
    try {
        const hshPswd = await hashPswd(password);
        const query = 'INSERT INTO Users (username, mobile_number, email, user_role, password_hash) VALUES (?,?,?,"customer",?)'
        const params = [username, mobile_number, email, hshPswd];
        await runDBCommand(query, params);
        res.status(201).json({ message: 'User registered successfully' })
    }
    catch (error) {
        console.error('Error during registration: ', error);
        if (error.code === 'ER_DUP_ENTRY') {
            return res.status(409).json({ error: 'User already exists' });
        }
        else {
            res.status(500);
            error.status = 500;
            error.message = 'Error in registering';
            console.error('Error in registering:', error);
            res.render('error.ejs', { error });
        }
    }
});

app.post('/auth', async (req, res) => {
    const { username, email, password } = req.body;
    if (!username || !email || !password) {
        req.session.message = "All fields are required!";
        res.redirect('/login');
    }

    try {
        const user = await runDBCommand('SELECT * FROM Users WHERE email = ?', [email]);
        if (user.length === 0) {
            req.session.message = "User not present!";
            return res.redirect('/login');
        }
        if (user[0].username !== username) {
            req.session.message = "Invalid Username!";
            return res.redirect('/login');
        }
        const isMatch = await verifyPswd(password, user[0].password_hash);
        if (!isMatch) {
            req.session.message = "Invalid Password!";
            return res.redirect('/login');
        }
        const token = generateToken(user[0], process.env.JWT_SECRET);
        if (!token) {
            req.session.message = "Failed to generate token!";
            return res.redirect('/login');
        }
        res.cookie('token', token, {
            maxAge: 60 * 60 * 1000,
            httpOnly: true,
            secure: false,
            sameSite: 'Lax'
        });
        if (user[0].user_role === "admin") {
            res.redirect('/admin')
        }
        else {
            res.redirect('/home');
        }

        console.log('User authenticated successfully:', user[0].username);;
    }
    catch (error) {
        console.error('Error during authentication:', error);
        req.session.message = "Error during authentication :: internal Server Error!";
        res.redirect('/login');
    }
})

app.post('/api/auth', async (req, res) => {
    const { username, email, password } = req.body;
    if (!username || !email || !password) {
        return res.status(400).json({ error: 'All fields are required' });
    }

    try {
        const user = await runDBCommand('SELECT * FROM Users WHERE email = ?', [email]);
        if (user.length === 0) {
            return res.status(404).json({ error: 'User not present' });
        }
        if (user[0].username !== username) {
            return res.status(401).json({ error: 'Invalid username' });
        }
        const isMatch = await verifyPswd(password, user[0].password_hash);
        if (!isMatch) {
            return res.status(401).json({ error: 'Invalid Password' });
        }
        const token = generateToken(user[0], process.env.JWT_SECRET);
        if (!token) {
            return res.status(500).json({ error: 'Failed to generate token' });
        }
        console.log('User authenticated successfully:', user[0].username);
        res.json({
            token, user: {
                id: user[0].id,
                username: user[0].username,
                mobile_number: user[0].mobile_number,
                email: user[0].email,
                user_role: user[0].user_role
            }
        });
    }
    catch (error) {
        res.status(500);
        error.status = 500;
        error.message = 'Error in authentication';
        console.error('Error during authentication:', error);
        res.render('error.ejs', { error });
    }
})

app.get('/admin', authenticateToken, async (req, res) => {
    if (req.user.user_role === "admin") {
        try {
            res.render('admin.ejs', { user: req.user });
        }
        catch (error) {
            res.status(500);
            error.status = 500;
            error.message = 'Error in fetching admin page';
            console.error('Error in fetching admin page:', error);
            res.render('error.ejs', { error });
        }
    }
    else {
        res.status(401).send("Forbidden")
    }
});

app.get('/home', authenticateToken, query('search').isLength({ min: 0, max: 16 }).withMessage('Search must be Less than 16 characters'), async (req, res) => {
    try {
        if (!req.user) {
            res.status(401);
            const error = new Error('Unauthorized access');
            error.status = 401;
            error.message = 'You must be logged in to access this page';
            console.error('Unauthorized access:', error.message);
            return res.render('error.ejs', { error });
        }
        const query = 'SELECT user_role FROM Users WHERE email = ?';
        const user_roleArr = await runDBCommand(query, [req.user.email])
        if (user_roleArr[0].user_role === 'chef' || user_roleArr[0].user_role === "admin") {
            const orders = await runDBCommand('SELECT * FROM Orders');
            const payments = await runDBCommand('SELECT payment_status FROM Payments WHERE order_id IN (SELECT id FROM Orders)')
            res.render('chef.ejs', { orders, payments , user: req.user });
        }
        else if (user_roleArr[0].user_role === 'customer') {
            const result = validationResult(req)
            if (result.errors[0]) {
                res.send(result.errors[0].msg)
            }
            let searchedProducts = ''
            let low = 0;
            let high = 1e4;
            let range = []
            if (Object.keys(req.query).length) {
                if (req.query.price !== "all") {
                    range = req.query.price.split('-')
                    low = range[0];
                    high = range[1];
                }
                const query1 = 'SELECT * FROM Products WHERE product_name LIKE ? AND price BETWEEN ? AND ?';
                searchedProducts = await runDBCommand(query1, [`%${req.query.search}%`, low, high])
            }
            const products = await runDBCommand('SELECT * FROM Products')
            res.render('home.ejs', { user: req.user, products: products, query: req.query.search, range, searchedProducts });
        }
    }
    catch (error) {
        res.status(500);
        error.status = 500;
        error.message = 'Error in fetching home page';
        console.error('Error in fetching home page:', error);
        res.render('error.ejs', { error });
    }
});

app.get('/users', authenticateToken, async (req, res) => {
    if (req.user.user_role === "admin") {
        try {
            let extra = 0;
            const users = await runDBCommand('SELECT * FROM Users');
            res.render('users.ejs', { users, extra , user: req.user });
        } catch (error) {
            res.status(500);
            error.status = 500;
            error.message = 'Error in fetching users';
            console.error('Error in fetching users:', error);
            res.render('error.ejs', { error });
        }
    }
    else {
        res.status(401).send("Forbidden")
    }
}
);

app.get('/users/:id', authenticateToken, async (req, res) => {
    if (req.user.user_role === "admin") {
        try {
            let extra = 1;
            const users = await runDBCommand('SELECT * FROM Users WHERE id=?', [req.params.id]);
            res.render('users.ejs', { users, extra , user:req.user});
        } catch (error) {
            res.status(500);
            error.status = 500;
            error.message = 'Error fetching user';
            console.error('Error fetching user:', error);
            res.render('error.ejs', { error });
        }
    }
    else {
        res.status(401).send("Forbidden")
    }
}
);

app.post('/add-to-cart/:id', authenticateToken, async (req, res) => {
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

app.post('/add-one-to-cart/:id', authenticateToken, async (req, res) => {
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

app.post('/remove-from-cart/:id', authenticateToken, async (req, res) => {
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

app.get('/cart', authenticateToken, async (req, res) => {
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

app.post('/api/cart/order', authenticateToken, async (req, res) => {
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
        res.redirect('/cart');
    }
    catch (error) {
        res.status(500);
        error.status = 500;
        error.message = 'Error in ordering';
        console.error('Error in ordering: ', error);
        res.render('error.ejs', { error });
    }
});

app.get('/orders', authenticateToken, async (req, res) => {
    try {
        const query1 = 'SELECT * FROM Users WHERE email = ?';
        const customer = await runDBCommand(query1, [req.user.email]);

        const query2 = 'SELECT * FROM Orders WHERE customer_id = ?';
        const orders = await runDBCommand(query2, [customer[0].id])

        const query3 = `
            SELECT DISTINCT p.product_name
            FROM Orders o
            JOIN OrderItems oi ON o.id = oi.order_id
            JOIN Products p ON oi.product_id = p.id
            WHERE o.customer_id = ?;
        `;

        const productRows = await runDBCommand(query3, [customer[0].id]);
        const productNames = productRows.map(row => row.product_name);

        const query4 = 'SELECT DISTINCT p.payment_status FROM Payments p JOIN Orders o ON p.order_id = o.id WHERE o.customer_id = ?';
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

app.get('/past-orders', authenticateToken, async (req, res) => {
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

app.post('/payment-done/:id', authenticateToken, async (req, res) => {
    try {
        const query = 'SELECT user_id FROM Payments WHERE id = ?';
        const user_id = await runDBCommand(query, [req.params.id])
        if (user_id[0].user_id === req.user.id) {
            const query2 = 'UPDATE Payments SET payment_status = "completed" WHERE id = ? AND user_id = ?';
            await runDBCommand(query2, [req.params.id, req.user.id]);
            res.redirect('/orders');
        }
        else {
            res.send(401).send('Authorization failure!')
        }
    }
    catch (error) {
        res.status(500);
        error.status = 500;
        error.message = 'Error in completing payment';
        console.error('Error in completing payment:', error);
        res.render('error.ejs', { error });
    }
});

app.get('/all-orders', authenticateToken, async (req, res) => {
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
app.get('/all-payments', authenticateToken, async (req, res) => {
    if (req.user.user_role === "admin") {
        try {
            const payments = await runDBCommand('SELECT * FROM Payments');
            res.render("all_payments.ejs", { payments , user: req.user });
        }
        catch (error) {
            res.status(500);
            error.status = 500;
            error.message = 'Error in fetching payments';
            console.error('Error in fetching payments:', error);
            res.render('error.ejs', { error });
        }
    }
    else {
        res.status(401).send("Forbidden access");
    }
});

app.post('/api/delete-order/:id', authenticateToken, async (req, res) => {
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

app.post('/api/delete-payment/:id', authenticateToken, async (req, res) => {
    let id = -1;
    try {

        if (req.user.user_role == "admin") {
            id = req.params.id;
            const query = 'DELETE FROM Payments WHERE id = ?';
            await runDBCommand(query, id);
            res.redirect('/all-payments');
        }
    }
    catch (error) {
        res.status(500);
        error.status = 500;
        error.message = 'Error in deleting payment';
        console.error('Error in deleting payment:', error);
        res.render('error.ejs', { error });
    }
});

app.post('/api/order-done/:id', async (req, res) => {
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

app.get('/categories', authenticateToken, async (req, res) => {
    try {
        let products = '';
        if (req.query.category) {
            if (req.query.category == "all") {
                const query = 'SELECT * FROM Products'
                products = await runDBCommand(query)
            }
            else {
                const query = 'SELECT * FROM Products WHERE category = ?';
                products = await runDBCommand(query, req.query.category);
            }
        }
        const categories = await runDBCommand('SELECT DISTINCT category FROM Products');
        res.render('categories.ejs', { user: req.user, categories, products  , user: req.user });
    }
    catch (error) {
        res.status(500);
        error.status = 500;
        error.message = 'Error in fetching categories';
        console.error('Error in fetching categories:', error);
        res.render('error.ejs', { error });
    }
});

app.get('/add-food', authenticateToken, (req, res) => {
    let msg = req.session.message;
    req.session.message = null;
    if (req.user.user_role === "admin" || req.user.user_role === "chef") {
        try {
            res.render('add_food.ejs', { user: req.user, msg });
        }
        catch (error) {
            res.status(500);
            error.status = 500;
            error.message = 'Error in fetching add food page';
            console.error('Error in fetching add food page:', error);
            res.render('error.ejs', { error });
        }
    }
    else {
        res.status(401).send('Forbidden Access')
    }
});

app.post('/api/add-food', authenticateToken, async (req, res) => {
    if (req.user.user_role === "admin" || req.user.user_role === "chef") {
        try {
            const { name, price, category, image_url } = req.body;
            if (!name || !price || !category) {
                return res.status(400).json({ error: 'All fields are required' });
            }
            if (name.length < 3 || name.length > 16) {
                return res.status(400).json({ error: 'Name length should be between 3 and 16' })
            }
            const query = 'INSERT INTO Products (product_name , price , category , image_url) VALUES (?,?,?,?)'
            await runDBCommand(query, [name, price, category, image_url]);
            req.session.message = "Food added successfully!";
            res.redirect('/add-food');
        }
        catch (error) {
            console.error('Error during registration: ', error);
            if (error.code === 'ER_DUP_ENTRY') {
                req.session.message = "Food already exists!";
                return res.redirect('/add-food');
            }
            else {
                res.status(500);
                error.status = 500;
                error.message = 'Error in adding food';
                console.error('Error in adding food:', error);
                res.render('error.ejs', { error });
            }
        }
    }
    else {
        res.status(401).send('Forbidden Access')
    }
});

app.post('/api/delete-user/:id', authenticateToken, async (req, res) => {
    if (req.user.user_role === "admin") {
        try {
            const query = 'DELETE FROM Users WHERE id = ?';
            await runDBCommand(query, [req.params.id])
            res.redirect('/users');
        }
        catch (error) {
            res.status(500);
            error.status = 500;
            error.message = 'Error in deleting user';
            console.error('Error in deleting user:', error);
            res.render('error.ejs', { error });
        }
    }
    else {
        if (req.user.id === req.params.id) {
            try {

                const query = 'DELETE FROM Users WHERE id = ?';
                await runDBCommand(query, [req.params.id]);
                res.redirect('/');
            }
            catch (error) {
                res.status(500);
                error.status = 500;
                error.message = 'Error in deleting user';
                console.error('Error in deleting user:', error);
                res.render('error.ejs', { error });
            }
        }
        else {
            res.status(401).send('Forbidden Access');
        }
    }

});

app.get('/edit-user/:id', authenticateToken, async (req, res) => {
    if (req.user.user_role === "admin") {
        try {
            const user = await runDBCommand('SELECT * FROM Users WHERE id = ?', [req.params.id])
            if (user.length === 0) {
                res.redirect('/users');
            }
            res.render('edit.ejs', { user: req.user , userTo: user[0], role: req.user.user_role });
        }
        catch (error) {
            rese.status(500);
            error.status = 500;
            error.message = 'Error in fetching user for edit';
            console.error('Error in fetching user for edit:', error);
            res.render('error.ejs', { error });
        }
    }
    else {
        if (req.user.id === req.params.id) {
            try {
                const user = await runDBCommand('SELECT * FROM Users WHERE id = ?', [req.user.id])
                res.render('edit.ejs', { user : req.user, userTo : user[0] , role: req.user.user_role });
            }
            catch (error) {
                res.status(500);
                error.status = 500;
                error.message = 'Error in fetching user for edit';
                console.error('Error in fetching user for edit:', error);
                res.render('error.ejs', { error });
            }
        }
        else {
            res.status(401).send('Forbidden Access');
        }
    }
});

app.post('/gen-bill/:id', authenticateToken, async (req, res) => {
    if (req.user.user_role === "admin") {
        try {
            const query = 'UPDATE Orders SET current_status = "accepted" WHERE id IN (SELECT order_id FROM Payments WHERE id = ?)';
            await runDBCommand(query, [req.params.id]);
            res.redirect('/all-payments');
        }
        catch (error) {
            res.status(500);
            error.status = 500;
            error.message = 'Error in generating bill';
            console.error('Error in generating bill:', error);
            res.render('error.ejs', { error });
        }
    }
    else {
        res.status(401).send('Forbidden Access');
    }
});


app.post('/edit-user', authenticateToken, async (req, res) => {
    if (req.user.user_role === "admin") {
        const { username, user_role, id } = req.body;
        if (!username || !user_role) {
            return res.status(400).json({ error: 'All fields are required' });
        }

        try {
            const query = 'UPDATE Users SET username = ?, user_role = ? WHERE id = ?'
            const params = [username, user_role, id];
            await runDBCommand(query, params);
            res.redirect('/users');
        }
        catch (error) {
            res.status(500);
            error.status = 500;
            error.message = 'Error in editing user';
            console.error('Error in editing user:', error);
            res.render('error.ejs', { error });
        }
    }
    else {
        res.status(400).send('Forbidden Access')
    }
});

app.post('/new-price/:id', authenticateToken, (req, res) => {
    if (req.user.user_role === "admin") {
        const { price } = req.body;

        if (!price) {
            const error = new Error('Price is required');
            error.status = 400;
            console.error('Price is required:', price);
            return res.status(400).render('error.ejs', { error });
        }

        if (isNaN(price) || price <= 0) {
            const error = new Error('Invalid price');
            error.status = 400;
            console.error('Invalid price:', price);
            return res.status(400).render('error.ejs', { error });
        }

        const query = 'UPDATE Products SET price = ? WHERE id = ?';
        runDBCommand(query, [price, req.params.id])
            .then(() => {
                return res.redirect('/categories');
            })
            .catch((error) => {
                error.status = 500;
                error.message = 'Error in updating price';
                console.error('Error in updating price:', error);
                return res.status(500).render('error.ejs', { error });
            });
    } else {
        const error = new Error('Unauthorized access');
        error.status = 403;
        error.message = 'You do not have permission to perform this action';
        console.error('Unauthorized access:', error.message);
        return res.status(403).render('error.ejs', { error });
    }
});

app.post('/delete-product/:id', authenticateToken, async (req, res) => {
    if (req.user.user_role === "admin") {
        try {
            const query = 'DELETE FROM Products WHERE id = ?';
            await runDBCommand(query, [req.params.id]);
            res.redirect('/categories');
        }
        catch (error) {
            res.status(500);
            error.status = 500;
            error.message = 'Error in deleting product';
            console.error('Error in deleting product:', error);
            res.render('error.ejs', { error });
        }
    }
    else {
        const error = new Error('Unauthorized access');
        error.status = 403;
        error.message = 'You do not have permission to perform this action';
        console.error('Unauthorized access:', error.message);
        return res.status(403).render('error.ejs', { error });
    }
}
);

app.post('/new-name/:id', authenticateToken, (req, res) => {
    if (req.user.user_role === "admin") {
        const { name } = req.body;

        if (!name) {
            const error = new Error('Name is required');
            error.status = 400;
            console.error('Name is required:', name);
            return res.status(400).render('error.ejs', { error });
        }
        if (name.length < 3 || name.length > 16) {
            const error = new Error('Invalid name');
            error.status = 400;
            console.error('Invalid name:', name);
            return res.status(400).render('error.ejs', { error });
        }

        const query = 'UPDATE Products SET product_name = ? WHERE id = ?';
        runDBCommand(query, [name, req.params.id])
            .then(() => {
                return res.redirect('/categories');
            })
            .catch((error) => {
                error.status = 500;
                error.message = 'Error in updating name';
                console.error('Error in updating name:', error);
                return res.status(500).render('error.ejs', { error });
            });
    } else {
        const error = new Error('Unauthorized access');
        error.status = 403;
        error.message = 'You do not have permission to perform this action';
        console.error('Unauthorized access:', error.message);
        return res.status(403).render('error.ejs', { error });
    }
});

app.get('/order/items/:id', authenticateToken, async (req, res) => {
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

app.get('/order/payment/:id', authenticateToken, async (req, res) => {
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

app.get('/order/bill/:id', authenticateToken, async (req, res) => {
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