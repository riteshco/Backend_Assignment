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
    res.render('index.ejs');
})

app.get('/login', (req, res) => {
    res.render('login.ejs');
});

app.get('/signup', (req, res) => {
    res.render('signup.ejs');
}
);

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
        // res.status(201).json({ message: 'User registered successfully' })
        res.redirect('/');
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
        res.redirect('/');
        
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