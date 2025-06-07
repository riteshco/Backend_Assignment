import express from 'express';
import db from './config/database.js';
import path from 'path';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';
import cookieParser from 'cookie-parser';
dotenv.config();
import { hashPswd, verifyPswd, generateToken, authenticateToken } from './utils/helpers.js';

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
        if(req.user){
            if( req.user.user_role === 'customer' || req.user.user_role === 'chef'){
                return res.redirect('/home');
            }
            else if (req.user.user_role === 'admin') {
                return res.redirect('/admin');
            }
        }
    }
    res.render('index.ejs');
})

app.get('/login', (req, res) => {
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
    try {
        const hshPswd = await hashPswd(password);
        const query = 'INSERT INTO Users (username, mobile_number, email, user_role, password_hash) VALUES (?,?,?,?,?)'
        const params = [username, mobile_number, email, user_role, hshPswd];
        await runDBCommand(query, params);
        res.redirect('/login');
    }
    catch (error) {
        console.error('Error during registration: ', error);
        if (error.code === 'ER_DU   _ENTRY') {
            return res.status(409).json({ error: 'User already exists' });
        }
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.post('/api/register', async (req, res) => {
    const { username, mobile_number, email, user_role, password } = req.body;
    if (!username || !mobile_number || !email || !user_role || !password) {
        return res.status(400).json({ error: 'All fields are required' });
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
        if (error.code === 'ER_DU   _ENTRY') {
            return res.status(409).json({ error: 'User already exists' });
        }
        res.status(500).json({ error: 'Internal Server Error' });
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
            httpOnly: true,
            secure: false,
            sameSite: 'Lax'
        });
        res.redirect('/home');
        
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

app.get('/home' , authenticateToken  , async (req, res) => {
    if (!req.user) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    const query = 'SELECT user_role FROM Users WHERE email = ?';
    const user_roleArr = await runDBCommand(query , [req.user.email])
    if(user_roleArr[0].user_role === 'chef'){
        const orders = await runDBCommand('SELECT * FROM Orders');
        console.log(orders)
        res.render('chef.ejs', {orders});
    }
    else if (user_roleArr[0].user_role === 'customer'){
        const products = await runDBCommand('SELECT * FROM Products')
        res.render('home.ejs', { user: req.user , products: products });
    }
});

app.get('/users', async (req, res) => {
    try {
        const users = await runDBCommand('SELECT * FROM Users');
        res.json(users);
    } catch (error) {
        console.error('Error fetching users:', error);
        res.status(500).send('Internal Server Error');
    }
}
);

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