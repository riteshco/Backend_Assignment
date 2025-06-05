import mysql from 'mysql2';
import dotenv from 'dotenv';
dotenv.config();

const dbConfig = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DATABASE,
});

dbConfig.connect((err) => {
  if (err) {
    throw err;
  }
  console.log('Connected to the database successfully');
});
export default dbConfig;