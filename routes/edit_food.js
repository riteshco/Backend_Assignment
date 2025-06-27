import express from 'express';
import { runDBCommand } from '../app.js';
import { authenticateToken } from '../utils/helpers.js';

const router = express.Router();

router.post('/new-price/:id', authenticateToken, (req, res) => {
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

router.post('/delete-product/:id', authenticateToken, async (req, res) => {
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

router.post('/new-name/:id', authenticateToken, (req, res) => {
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

export default router;
