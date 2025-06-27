import express from 'express';
import { runDBCommand } from '../app.js';
import dotenv from 'dotenv';
dotenv.config();
import { authenticateToken } from '../utils/helpers.js';

const router = express.Router();

router.get('/add-food', authenticateToken, (req, res) => {
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

router.post('/api/add-food', authenticateToken, async (req, res) => {
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

export default router;