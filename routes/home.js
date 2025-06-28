import express from "express";
import { runDBCommand } from '../app.js';
import dotenv from 'dotenv';
dotenv.config();
import { authenticateToken } from '../utils/helpers.js';
import { query, validationResult } from 'express-validator';

const router = express.Router();

router.get('/home', authenticateToken, query('search').trim().isLength({ min: 0, max: 16 }).withMessage('Search must be Less than 16 characters'), async (req, res) => {
        try {
            if (!req.user) {
                res.status(401);
                const error = new Error('Unauthorized access');
                error.status = 401;
                error.message = 'You must be logged in to access this page';
                console.error('Unauthorized access:', error.message);
                return res.render('error.ejs', { error });
            }
            if(req.user.user_role === "admin"){
                return res.redirect('/admin');
            }
        const query = 'SELECT user_role FROM Users WHERE email = ?';
        const user_roleArr = await runDBCommand(query, [req.user.email])
        if (user_roleArr[0].user_role === 'chef' || user_roleArr[0].user_role === "admin") {
            const orders = await runDBCommand('SELECT * FROM Orders');
            const payments = await runDBCommand('SELECT payment_status FROM Payments WHERE order_id IN (SELECT id FROM Orders)')
            res.render('chef.ejs', { orders, payments , user: req.user });
        }
        else if (user_roleArr[0].user_role === 'customer') {
            let msg = req.session.message;
            req.session.message = null;
            const result = validationResult(req)
            if (result.errors[0]) {
                res.send(result.errors[0].msg)
            }
            let searchedProducts = ''
            let low = 0;
            let high = 1e4;
            let range = []
            if (Object.keys(req.query).length) {
                req.query.search = req.query.search.trim();
                if (req.query.price !== "all") {
                    range = req.query.price.split('-')
                    low = range[0];
                    high = range[1];
                }
                const query1 = 'SELECT * FROM Products WHERE product_name LIKE ? AND price BETWEEN ? AND ?';
                searchedProducts = await runDBCommand(query1, [`%${req.query.search}%`, low, high])
            }
            const products = await runDBCommand('SELECT * FROM Products')
            res.render('home.ejs', { user: req.user, products: products, query: req.query.search, range, searchedProducts , msg });
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

export default router;