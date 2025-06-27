import express from 'express';
import { runDBCommand } from '../app.js';
import dotenv from 'dotenv';
dotenv.config();
import { authenticateToken } from '../utils/helpers.js';

const router = express.Router();

router.post('/payment-done/:id', authenticateToken, async (req, res) => {
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


router.get('/all-payments', authenticateToken, async (req, res) => {
    if (req.user.user_role === "admin") {
        try {
            const msg = req.session.msg;
            req.session.msg = null;
            const payments = await runDBCommand('SELECT * FROM Payments');
            res.render("all_payments.ejs", { payments , user: req.user , msg});
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

router.post('/api/delete-payment/:id', authenticateToken, async (req, res) => {
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

export default router;