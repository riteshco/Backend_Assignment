import mysql from 'mysql2';
import dotenv from 'dotenv';
dotenv.config();

const dbConfig = mysql.createConnection({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

dbConfig.connect(function(err) {
  if (err) {
   console.error(err);
   throw err;
  }
  console.log('Connected to the database successfully');
});
const db = dbConfig.promise();
export default db;