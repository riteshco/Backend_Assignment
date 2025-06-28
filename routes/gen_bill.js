import express from 'express';
import { runDBCommand } from '../app.js';
import { authenticateToken } from '../utils/helpers.js';

const router = express.Router();

router.post('/gen-bill/:id', authenticateToken, async (req, res) => {
    if (req.user.user_role === "admin") {
        try {
            const query = 'UPDATE Orders SET current_status = "accepted" WHERE id IN (SELECT order_id FROM Payments WHERE id = ?)';
            await runDBCommand(query, [req.params.id]);
            req.session.msg = 'Bill generated successfully';
            res.redirect('/all-payments');
        }
        catch (error) {
            res.status(500);
            error.status = 500;
            error.message = 'Error in generating bill';
            console.error('Error in generating bill:', error);
            res.render('error.ejs', { error });
        }
    }
    else {
        res.status(403).send('Forbidden Access');
    }
}); 

export default router;