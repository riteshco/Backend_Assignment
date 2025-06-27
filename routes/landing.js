import express from 'express';
import dotenv from 'dotenv';
dotenv.config();
import jwt from 'jsonwebtoken';

const router = express.Router();

router.get('/', (req, res) => {    
    if (req.cookies.token) {
        try {
            const user = jwt.verify(req.cookies.token, process.env.JWT_SECRET);
            if (user.user_role === 'customer' || user.user_role === 'chef') {
                return res.redirect('/home');
            }
            else if (user.user_role === 'admin') {
                return res.redirect('/admin');
            }
        }
        catch (error) {
            console.error('Invalid token:', error.message);
            res.send('Invalid Token!')
        }
    }
    res.render('index.ejs');
})

export default router;