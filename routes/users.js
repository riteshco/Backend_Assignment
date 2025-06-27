import express from 'express';
import { runDBCommand } from '../app.js';
import dotenv from 'dotenv';
dotenv.config();
import { authenticateToken } from '../utils/helpers.js';

const router = express.Router();

router.get('/users', authenticateToken, async (req, res) => {
    if (req.user.user_role === "admin") {
        try {
            let extra = 0;
            const users = await runDBCommand('SELECT * FROM Users');
            res.render('users.ejs', { users, extra , user: req.user });
        } catch (error) {
            res.status(500);
            error.status = 500;
            error.message = 'Error in fetching users';
            console.error('Error in fetching users:', error);
            res.render('error.ejs', { error });
        }
    }
    else {
        res.status(401).send("Forbidden")
    }
}
);

router.get('/users/:id', authenticateToken, async (req, res) => {
    if (req.user.user_role === "admin") {
        try {
            let extra = 1;
            const users = await runDBCommand('SELECT * FROM Users WHERE id=?', [req.params.id]);
            res.render('users.ejs', { users, extra , user:req.user});
        } catch (error) {
            res.status(500);
            error.status = 500;
            error.message = 'Error fetching user';
            console.error('Error fetching user:', error);
            res.render('error.ejs', { error });
        }
    }
    else {
        res.status(401).send("Forbidden")
    }
}
);

export default router;