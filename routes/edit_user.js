import express from 'express';
import { runDBCommand } from '../app.js';
import { authenticateToken } from '../utils/helpers.js';

const router = express.Router();

router.post('/api/delete-user/:id', authenticateToken, async (req, res) => {
    if (req.user.user_role === "admin") {
        try {
            const query = 'DELETE FROM Users WHERE id = ?';
            await runDBCommand(query, [req.params.id])
            res.redirect('/users');
        }
        catch (error) {
            res.status(500);
            error.status = 500;
            error.message = 'Error in deleting user';
            console.error('Error in deleting user:', error);
            res.render('error.ejs', { error });
        }
    }
    else {
        if (req.user.id === req.params.id) {
            try {

                const query = 'DELETE FROM Users WHERE id = ?';
                await runDBCommand(query, [req.params.id]);
                res.redirect('/');
            }
            catch (error) {
                res.status(500);
                error.status = 500;
                error.message = 'Error in deleting user';
                console.error('Error in deleting user:', error);
                res.render('error.ejs', { error });
            }
        }
        else {
            res.status(403).send('Forbidden Access');
        }
    }

});

router.get('/edit-user/:id', authenticateToken, async (req, res) => {
    if (req.user.user_role === "admin") {
        try {
            const user = await runDBCommand('SELECT * FROM Users WHERE id = ?', [req.params.id])
            if (user.length === 0) {
                res.redirect('/users');
            }
            res.render('edit.ejs', { user: req.user , userTo: user[0], role: req.user.user_role });
        }
        catch (error) {
            res.status(500);
            error.status = 500;
            error.message = 'Error in fetching user for edit';
            console.error('Error in fetching user for edit:', error);
            res.render('error.ejs', { error });
        }
    }
    else {
        if (req.user.id === req.params.id) {
            try {
                const user = await runDBCommand('SELECT * FROM Users WHERE id = ?', [req.user.id])
                res.render('edit.ejs', { user : req.user, userTo : user[0] , role: req.user.user_role });
            }
            catch (error) {
                res.status(500);
                error.status = 500;
                error.message = 'Error in fetching user for edit';
                console.error('Error in fetching user for edit:', error);
                res.render('error.ejs', { error });
            }
        }
        else {
            res.status(403).send('Forbidden Access');
        }
    }
});

router.post('/edit-user', authenticateToken, async (req, res) => {
    if (req.user.user_role === "admin") {
        let { username, user_role, id } = req.body;
        if (!username || !user_role) {
            return res.status(400).json({ error: 'All fields are required' });
        }

        username = username.trim();
        user_role = user_role.trim();

        if (username.length < 3 || username.length > 16) {
            res.status(400);
            error.status = 400;
            error.message = 'Username length should be between 3 and 16';
            console.error('Username length should be between 3 and 16');
            res.render('error.ejs', { error });
        }

        try {
            if(user_role === "chef"){
                const query1 = 'DELETE FROM Orders WHERE customer_id = ? AND current_status != "delivered"';
                await runDBCommand(query1, [id]);
            }
            const query = 'UPDATE Users SET username = ?, user_role = ? WHERE id = ?'
            const params = [username, user_role, id];
            await runDBCommand(query, params);
            res.redirect('/users');
        }
        catch (error) {
            res.status(500);
            error.status = 500;
            error.message = 'Error in editing user';
            console.error('Error in editing user:', error);
            res.render('error.ejs', { error });
        }
    }
    else {
        res.status(403).send('Forbidden Access')
    }
});

export default router;