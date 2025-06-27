import express from 'express';
import { runDBCommand } from '../app.js';
import { authenticateToken } from '../utils/helpers.js';

const router = express.Router();

router.get('/categories', authenticateToken, async (req, res) => {
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

export default router;