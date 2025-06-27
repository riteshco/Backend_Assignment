import express from 'express';
import { runDBCommand } from '../app.js';
import dotenv from 'dotenv';
dotenv.config();
import { hashPswd } from '../utils/helpers.js';
import { query } from 'express-validator';

const router = express.Router();

router.get('/signup', (req, res) => {
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

router.post('/register', async (req, res) => {
    let { username, mobile_number, email, password } = req.body;
    if (!username || !mobile_number || !email || !password) {
        return res.status(400).json({ error: 'All fields are required' });
    }
    
    username = username.trim();
    email = email.trim();
    password = password.trim();

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

router.post('/api/register', query(), async (req, res) => {
    let { username, mobile_number, email, password } = req.body;
    if (!username || !mobile_number || !email || !password) {
        return res.status(400).json({ error: 'All fields are required' });
    }

    username = username.trim();
    email = email.trim();
    password = password.trim();

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

export default router;