import express from 'express';
import { runDBCommand } from '../app.js';
import dotenv from 'dotenv';
dotenv.config();
import { verifyPswd, generateToken } from '../utils/helpers.js';
import jwt from 'jsonwebtoken';

const router = express.Router();

router.get('/login', (req, res) => {
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

router.post('/auth', async (req, res) => {
    if(req.cookies.token){
        console.log('Clearing existing token cookie');
        res.clearCookie('token');
    }
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

router.post('/api/auth', async (req, res) => {
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

router.post('/api/logout', (req, res) => {
    res.clearCookie('token');
    res.redirect('/');
}
);

export default router;