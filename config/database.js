import mysql from 'mysql2';
import dotenv from 'dotenv';
dotenv.config();

const dbConfig = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
}).promise();

dbConfig.connect(function(err) {
  if (err) {
   throw err;
  }
  console.log('Connected to the database successfully');
});
export default dbConfig;

const result = await dbConfig.query('SELECT * FROM test_table');
console.log(result[0]);
