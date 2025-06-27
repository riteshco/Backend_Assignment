import express from 'express';
import db from './config/database.js';
import path from 'path';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';
import cookieParser from 'cookie-parser';
dotenv.config();
import session from 'express-session';

const port = 8080;

const app = express();

app.use(session({
    secret: process.env.JWT_SECRET,
    resave: false,
    saveUninitialized: true,
}));

app.set('view engine', 'ejs');

app.use(cookieParser());
app.use(express.urlencoded());
app.use(express.json());

app.use((req, res, next) => {
  if (req.headers.accept && req.headers.accept.includes('text/html')) {
    const cleanPath = req.path.split('/')[1];
    res.locals.currentPage = cleanPath;
}
else{
    res.locals.currentPage = '';
}
  res.locals.user = req.user || null;
  res.locals.message = req.session.message || null;
  next();
});

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
app.use(express.static(path.join(__dirname, 'public')));


export const runDBCommand = async (query, params = []) => {
    try {
        const [rows] = await db.query(query, params);
        return rows;
    } catch (err) {
        throw err;
    }
};

app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
}
);

import landingRoute from './routes/landing.js';
app.use('/', landingRoute);

import signingRoute from './routes/signing.js';
app.use('/', signingRoute);

import loginRoute from './routes/login.js';
app.use('/', loginRoute);

import adminRoute from './routes/admin.js';
app.use('/', adminRoute);

import homeRoute from './routes/home.js';
app.use('/', homeRoute);

import usersRoute from './routes/users.js';
app.use('/', usersRoute);

import cartRoute from './routes/cart.js';
app.use('/', cartRoute);

import orderRoute from './routes/order.js';
app.use('/', orderRoute);

import paymentRoute from './routes/payment.js';
app.use('/', paymentRoute);

import addFoodRoute from './routes/add_food.js';
app.use('/', addFoodRoute);

import categoriesRoute from './routes/categories.js';
app.use('/', categoriesRoute);

import editUserRoute from './routes/edit_user.js';
app.use('/', editUserRoute);

import editFoodRoute from './routes/edit_food.js';
app.use('/', editFoodRoute);

import genBillRoute from './routes/gen_bill.js';
app.use('/', genBillRoute);