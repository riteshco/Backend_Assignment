import express from 'express';
import dotenv from 'dotenv';
dotenv.config();
import { authenticateToken } from '../utils/helpers.js';

const router = express.Router();

router.get('/admin', authenticateToken, async (req, res) => {
    if (req.user.user_role === "admin") {
        try {
            res.render('admin.ejs', { user: req.user });
        }
        catch (error) {
            res.status(500);
            error.status = 500;
            error.message = 'Error in fetching admin page';
            console.error('Error in fetching admin page:', error);
            res.render('error.ejs', { error });
        }
    }
    else {
        res.status(403).send("Forbidden")
    }
});

export default router;