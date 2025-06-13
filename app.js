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

const port = 8080;


const app = express();

app.set('view engine', 'ejs');

app.use(cookieParser());
app.use(express.urlencoded());
app.use(express.json());

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
   if(req.cookies.token) {
       try{
            const user = jwt.verify(req.cookies.token , process.env.JWT_SECRET);
            if( user.user_role === 'customer' || user.user_role === 'chef'){
                return res.redirect('/home');
            }
            else if (user.user_role === 'admin') {
                return res.redirect('/admin');
            }
        }
        catch (error){
            console.error('Invalid token:' , error.message);
            res.send('Invalid Token!')
        }
    }
    res.render('index.ejs');      
})

app.get('/login', (req, res) => {
    if(req.cookies.token) {
        try{
            const user = jwt.verify(req.cookies.token , process.env.JWT_SECRET);
            if( user.user_role === 'customer' || user.user_role === 'chef'){
                return res.redirect('/home');
            }
            else if (user.user_role === 'admin') {
                return res.redirect('/admin');
            }
        }
        catch (error){
            console.error('Invalid token:' , error.message);
            res.send('Invalid Token!')
        }
    }
    res.render('login.ejs');
});

app.get('/signup', (req, res) => {
    if(req.cookies.token) {
        if(req.user){
            if( req.user.user_role === 'customer' || req.user.user_role === 'chef'){
                return res.redirect('/home');
            }
            else if (req.user.user_role === 'admin') {
                return res.redirect('/admin');
            }
        }
    }
    res.render('signup.ejs');
}
);

app.post('/api/logout', (req, res) => {
    res.clearCookie('token');
    res.redirect('/');
}
);

app.post('/register' , async (req, res)=>{
    const {username , mobile_number, email, user_role, password} = req.body;
    if (!username || !mobile_number || !email || !user_role || !password) {
        return res.status(400).json({ error: 'All fields are required' });
    }
    if(mobile_number.length != 10){
        return res.status(400).json({error: 'Invalid mobile number'})
    }
    if(password.length < 8){
        return res.status(400).send('Password Length should be greater than equal to 8')
    }
    try {
        const hshPswd = await hashPswd(password);
        const query = 'INSERT INTO Users (username, mobile_number, email, user_role, password_hash) VALUES (?,?,?,?,?)'
        const params = [username, mobile_number, email, user_role, hshPswd];
        await runDBCommand(query, params);
        res.redirect('/login');
    }
    catch (error) {
        console.error('Error during registration: ', error);
        if (error.code === 'ER_DUP_ENTRY') {
            return res.status(409).json({ error: 'User already exists' });
        }
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.post('/api/register',query() ,async (req, res) => {
    const { username, mobile_number, email, user_role, password } = req.body;
    if (!username || !mobile_number || !email || !user_role || !password) {
        return res.status(400).json({ error: 'All fields are required' });
    }
    if(mobile_number.length != 10){
        return res.status(400).json({error: 'Invalid mobile number'})
    }
    if(password.length < 8){
        return res.status(400).send('Password Length should be greater than equal to 8')
    }
    try {
        const hshPswd = await hashPswd(password);
        const query = 'INSERT INTO Users (username, mobile_number, email, user_role, password_hash) VALUES (?,?,?,?,?)'
        const params = [username, mobile_number, email, user_role, hshPswd];
        await runDBCommand(query, params);
        res.status(201).json({ message: 'User registered successfully' })
    }
    catch (error) {
        console.error('Error during registration: ', error);
        if (error.code === 'ER_DUP_ENTRY') {
            return res.status(409).json({ error: 'User already exists' });
        }
        else{
            res.status(500).json({ error: 'Internal Server Error' });
        }
    }
});

app.post('/auth', async (req, res) => {
    const { username, email, password } = req.body;
    if (!username || !email || !password) {
        return res.status(400).json({ error: 'All fields are required' });
    }

    try {
        const user = await runDBCommand('SELECT * FROM Users WHERE email = ?', [email]);
        if (user.length === 0) {
            return res.status(404).json({ error: 'User not found' });
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
        res.cookie('token', token, {
            maxAge: 60 * 60 * 1000,
            httpOnly: true,
            secure: false,
            sameSite: 'Lax'
        });
        if(user[0].user_role === "admin"){
            res.redirect('/admin')
        }
        else{
            res.redirect('/home');
        }
        
        console.log('User authenticated successfully:', user[0].username);;
    }
    catch (error) {
        console.error('Error during authentication:', error);
        res.status(500).json({ error: 'Internal Server Error' });
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
            return res.status(404).json({ error: 'User not found' });
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
        console.error('Error during authentication:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
})

app.get('/admin' , authenticateToken , async(req , res)=>{
    if(req.user.user_role === "admin"){
        try{
            res.render('admin.ejs' , {user:req.user});
        }
        catch (error) {
            console.error("Error in :" , error.message);
            res.status(500).send("Server Error!")
        }
    }
    else{
        res.status(401).send("Forbidden")
    }
});

app.get('/home' , authenticateToken , query('search').isLength({min : 0 , max: 16 }).withMessage('Search must be Less than 16 characters') , async (req, res) => {
    if (!req.user) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    const query = 'SELECT user_role FROM Users WHERE email = ?';
    const user_roleArr = await runDBCommand(query , [req.user.email])
    if(user_roleArr[0].user_role === 'chef' || user_roleArr[0].user_role === "admin"){
        const orders = await runDBCommand('SELECT * FROM Orders');
        const payments = await runDBCommand('SELECT payment_status FROM Payments WHERE order_id IN (SELECT id FROM Orders)')
        res.render('chef.ejs', {orders , payments});
    }
    else if (user_roleArr[0].user_role === 'customer'){ 
        const result = validationResult(req)
        if(result.errors[0]){
            res.send(result.errors[0].msg)
        }
        let searchedProducts = ''
        let low = 0;
        let high = 1e4;
        let range = []
        if(Object.keys(req.query).length){
            if(req.query.price !== "all"){
                range = req.query.price.split('-')
                low = range[0];
                high = range[1];
            }
            const query1 = 'SELECT * FROM Products WHERE product_name LIKE ? AND price BETWEEN ? AND ?';
            searchedProducts = await runDBCommand(query1 , [`%${req.query.search}%` , low , high])
        }
        const products = await runDBCommand('SELECT * FROM Products')
        res.render('home.ejs', { user: req.user , products: products , query: req.query.search , range, searchedProducts});
    }
});

app.get('/users',authenticateToken ,async (req, res) => {
    if(req.user.user_role === "admin"){
        try {
            let extra = 0;
            const users = await runDBCommand('SELECT * FROM Users');
            res.render('users.ejs' , {users , extra})
        } catch (error) {
            console.error('Error fetching users:', error);
            res.status(500).send('Internal Server Error');
        }
    }
    else{
        res.status(401).send("Forbidden")
    }
}
);

app.get('/users/:id',authenticateToken ,async (req, res) => {
    if(req.user.user_role === "admin"){
        try {
            let extra = 1;
            const users = await runDBCommand('SELECT * FROM Users WHERE id=?' , [req.params.id]);
            res.render('users.ejs' , {users , extra});
        } catch (error) {
            console.error('Error fetching users:', error);
            res.status(500).send('Internal Server Error');
        }
    }
    else{
        res.status(401).send("Forbidden")
    }
}
);

app.post('/add-to-cart/:id' , authenticateToken , async(req , res)=>{
    try{
        const productID = req.params.id;
        const quantity = req.body.quantity;
        const customerID = req.user.id;
        const query = 'INSERT INTO OrderItems (customer_id , product_id , quantity) VALUES (? , ? , ?)';
        await runDBCommand(query , [customerID , productID , quantity]);
        res .redirect('/home');
    }
    catch (error){
        console.error('Error in ordering: ' , error);
        res.status(500).send('Internal Server Error');
    }
});

app.get('/cart' , authenticateToken , async(req , res)=>{
    try{
        const query = 'SELECT * FROM OrderItems WHERE customer_id = ? AND order_id IS NULL';
        const orderedItems = await runDBCommand(query , [req.user.id]);
        res.render('cart.ejs' , {orderedItems});
    }
    catch (error){
        console.error('Error in ordering: ' , error);
        res.status(500).send('Internal Server Error');
    }
});

app.post('/api/cart/order' , authenticateToken , async(req , res)=>{
    const {table_number , instructions} = req.body;
    if(!table_number){
        res.status(401).send("Must give table number!")
    }
    try{
        const query = 'SELECT * FROM OrderItems WHERE customer_id = ? AND order_id IS NULL'
        const cartItems = await runDBCommand( query , [req.user.id] );
        const seconds = Math.floor(Date.now() % 100);
        let order_id = table_number + seconds + cartItems[0].id;

        const query2 = 'INSERT INTO Orders (id, customer_id , table_number , instructions) VALUES (? , ? , ? , ?)';
        await runDBCommand(query2 , [order_id, req.user.id , table_number , instructions]);

        const query3 = 'UPDATE OrderItems SET order_id = ? WHERE customer_id = ? AND order_id IS NULL';
        await runDBCommand(query3 , [order_id , req.user.id])

        res.redirect('/cart');
    }
    catch (error){  
        console.error('Error in ordering: ' , error);
        res.status(500).send('Internal Server Error');
    }
});

app.post('/api/order', authenticateToken , async (req , res)=> {
    try {
        const id = req.body.productId;
        const table_number = req.body.table_number;
        const instructions = req.body.instructions;
        const query = 'SELECT * FROM Products WHERE id = ?';
        const query2 = 'SELECT * FROM Users WHERE email = ?'
        const product = await runDBCommand(query , id);
        const customer = await runDBCommand(query2 , req.user.email);

        const seconds = Math.floor(Date.now() % 100);
        let order_id = table_number + seconds + product[0].id;

        const query3 = 'INSERT INTO Orders (id, customer_id , table_number , instructions) VALUES (? , ? , ? , ?)';
        await runDBCommand(query3 , [order_id, customer[0].id , table_number , instructions]);

        const query4 = 'INSERT INTO OrderItems (order_id , product_id) VALUES (? , ?)';
        await runDBCommand(query4 , [order_id , product[0].id])

        res.redirect('/home')           
    }
    catch (error) {
        console.error('Error in ordering: ' , error);
        res.status(500).send('Internal Server Error');
    }
});

app.get('/orders', authenticateToken, async (req, res) => {
    try {
        const query1 = 'SELECT * FROM Users WHERE email = ?';
        const customer = await runDBCommand(query1, [req.user.email]);

        const query2 = 'SELECT * FROM Orders WHERE customer_id = ?';
        const orders = await runDBCommand(query2 , [customer[0].id])

        const query3 = `
            SELECT DISTINCT p.product_name
            FROM Orders o
            JOIN OrderItems oi ON o.id = oi.order_id
            JOIN Products p ON oi.product_id = p.id
            WHERE o.customer_id = ?;
        `;

        const productRows = await runDBCommand(query3, [customer[0].id]);
        const productNames = productRows.map(row => row.product_name);

        res.render('orders.ejs', {orders , productNames });

    } catch (err) {
        console.error(err);
        res.status(500).send('Server error');
    }
});

app.get('/payment', authenticateToken , async (req , res) =>{
    try{
        const query = 'SELECT * FROM Payments WHERE user_id = ?'
        const payments = await runDBCommand(query , [req.user.id]);
        res.render('payment.ejs' , {payments:payments});
    }
    catch (error) {
        console.log(error);
        res.status(500).send('Server error');
    }
});

app.post('/payment-done/:id', authenticateToken, async (req , res)=>{
    try {
        const query = 'SELECT user_id FROM Payments WHERE id = ?';
        const user_id = await runDBCommand(query , [req.params.id])
        if(user_id[0].user_id === req.user.id){
            const query2 = 'UPDATE Payments SET payment_status = "completed" WHERE id = ? AND user_id = ?';
            await runDBCommand(query2 , [req.params.id , req.user.id]);
            res.redirect('/payment');
        }
        else{
            res.send(401).send('Authorization failure!')
        }
    }
    catch (error) {
        console.log(error);
        res.status(500).send('Server Error');
    }
});

app.get('/all-orders' , authenticateToken , async (req , res)=>{
    if(req.user.user_role === "admin"){
        try{
            const orders = await runDBCommand('SELECT * FROM Orders');             
            res.render('all_orders.ejs' , {orders});
        }
        catch (err) {
            console.error(err);
            res.status(500).send('Server error');
        }
    }
    else{
        res.status(401).send("Forbidden Access")
    }
});
app.get('/all-payments' , authenticateToken , async (req , res)=>{
    if(req.user.user_role === "admin"){
        try{
            const payments = await runDBCommand('SELECT * FROM Payments');
            res.render("all_payments.ejs" , {payments});
        }
        catch (error) {
            console.error(error);
            res.status(500).send('Server error');
        }
    }
    else{
        res.status(401).send("Forbidden access");
    }
});

app.post('/api/delete-order/:id' , authenticateToken , async (req , res)=>{
    let id = -1;
    if(req.user.user_role === "admin"){
        id = req.params.id;
        const query = 'DELETE FROM Orders WHERE id = ?';
        await runDBCommand(query , id);
        res.redirect('/all-orders');
    }
    if(req.user.user_role === "customer"){
        const orders = await runDBCommand('SELECT id FROM Orders WHERE customer_id = ?', req.user.id);
        if(orders.some(order => order.id == req.params.id)){
            id = req.params.id;
            const query = 'DELETE FROM Orders WHERE id = ?';
            await runDBCommand(query , id)
            res.redirect('/orders') 
        }
        else{
            res.status(401).send("User not allowed for this order!")
        }
    }       
});

app.post('/api/delete-payment/:id' , authenticateToken , async (req , res)=>{
    let id = -1;
    if(req.user.user_role == "admin"){
        id = req.params.id;
        const query = 'DELETE FROM Payments WHERE id = ?';
        await runDBCommand(query , id);
        res.redirect('/all-payments');
    }
});

app.post('/api/order-done/:id' , async (req , res)=> {
    const query = 'UPDATE Orders SET current_status = "delivered" WHERE id = ?';
    await runDBCommand(query , [req.params.id]);
    res.redirect('/home');
});

app.get('/categories', authenticateToken , async (req , res)=>{
    try{
        let products = '';
        if(req.query.category){
            if(req.query.category == "all"){
                const query = 'SELECT * FROM Products'
                products = await runDBCommand(query)
            }
                else{
                const query = 'SELECT * FROM Products WHERE category = ?';
                products = await runDBCommand(query , req.query.category);
            }
        }
        const categories = await runDBCommand('SELECT DISTINCT category FROM Products');
        res.render('categories.ejs' , {user : req.user , categories , products});
    }
    catch (error){
        console.error(error);
        res.status(500).send("Server error");
    }
});

app.get('/add-food', authenticateToken , (req , res)=> {
    if(req.user.user_role === "admin" || req.user.user_role === "chef"){
        try{
            res.render('add_food.ejs' , {user:req.user});
        }
        catch (error){
            console.error(error.message);
            res.status(500).send('Server Error')
        }
    }
    else{
        res.status(401).send('Forbidden Access')
    }
});

app.post('/api/add-food' , authenticateToken , async (req , res)=>{
        if(req.user.user_role === "admin" || req.user.user_role === "chef"){
        try{
            const {name , price , category , image_url} = req.body;
            if(!name || !price || !category){
                return res.status(400).json({ error: 'All fields are required' });
            }
            if(name.length < 3 || name.length > 16){
                return res.status(400).json({error : 'Name length should be between 3 and 16'})
            }
            const query = 'INSERT INTO Products (product_name , price , category , image_url) VALUES (?,?,?,?)'
            await runDBCommand(query , [name , price , category , image_url]);
            res.redirect('/add-food');  
        }
        catch (error){
            console.error('Error during registration: ', error);
            if (error.code === 'ER_DUP_ENTRY') {
                return res.status(409).json({ error: 'User already exists' });
            }
            else{
                res.status(500).json({ error: 'Internal Server Error' });
                    }
        }
    }
    else{
        res.status(401).send('Forbidden Access')
    }
});

app.post('/api/delete-user/:id', authenticateToken , async (req , res)=>{
    if(req.user.user_role === "admin"){
        try{
            const query = 'DELETE FROM Users WHERE id = ?';
            await runDBCommand(query , [req.params.id])
            res.redirect('/users');
        }
        catch (error) {
            console.log("Error : " , error.message);
            res.status(500).send({Error : 'Server Error'});
        }
    }
    else {
        if(req.user.id === req.params.id){
            try{

                const query = 'DELETE FROM Users WHERE id = ?';
                await runDBCommand(query , [req.params.id]);
                res.redirect('/');
            }
            catch (error){
                console.log("Error : " , error.message);
                res.status(500).send({Error : 'Server Error'})
            }
        }
        else{
            res.status(401).send('Forbidden Access');
        }
    }

});

app.get('/edit-user/:id', authenticateToken , async (req , res)=> {
    if(req.user.user_role === "admin"){
        try{
            const user = await runDBCommand('SELECT * FROM Users WHERE id = ?' , [req.params.id])
            if(user.length === 0){
                res.redirect('/users');
            }
            res.render('edit.ejs' , {user : user[0], role:req.user.user_role});
        }
        catch (error){
            console.log("Error : " , error.message);
            res.status(500).send({Error : 'Server Error'})
        }
    }
    else {
        if(req.user.id === req.params.id){
            try{
                const user = await runDBCommand('SELECT * FROM Users WHERE id = ?' , [req.user.id])
                res.render('edit.ejs' , {user , role:req.user.user_role});
            }
            catch (error) {
            console.log("Error : " , error.message);
            res.status(500).send({Error : 'Server Error'})
            }
        }
        else{
            res.status(401).send('Forbidden Access');
        }
    }
});

app.post('/gen-payment/:id', authenticateToken , async (req , res)=> {
    if(req.user.user_role === "admin"){
        try{
            const order = await runDBCommand('SELECT * FROM Orders WHERE id = ?' , [req.params.id])
            if(order.length === 0){
                res.redirect('/all-orders');
            }
            await runDBCommand('UPDATE Orders SET current_status = "accepted" WHERE id = ? ' , [req.params.id]);

            const orderItems = await runDBCommand('SELECT * FROM OrderItems WHERE order_id = ?' , [req.params.id]);
            const product = await runDBCommand('SELECT price FROM Products WHERE id = ?' , [orderItems[0].product_id])

            const query1 = 'INSERT INTO Payments (user_id , order_id , Total_amount) VALUES (?,?,?)';
            await runDBCommand(query1 , [order[0].customer_id , req.params.id , product[0].price * orderItems[0].quantity]);
            res.redirect('/all-orders');
        }
        catch (error){
            console.log("Error : " , error.message);
            res.status(500).send({Error : 'Server Error'})
        }
    }
    else {
        res.status(401).send('Forbidden Access');
    }
});


app.post('/edit-user' , authenticateToken , async (req , res)=>{
    if(req.user.user_role === "admin"){
        const {username , user_role , id} = req.body;
        if (!username || !user_role) {
            return res.status(400).json({ error: 'All fields are required'});
    }

    try {
        const query = 'UPDATE Users SET username = ?, user_role = ? WHERE id = ?'
        const params = [username, user_role , id];
        await runDBCommand(query, params);
        res.redirect('/users');
    }
    catch (error) {
        console.error('Error during registration: ', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
    }
    else{
        res.status(400).send('Forbidden Access')
    }
});