require('dotenv').config();
const fs = require('fs');
const mysql = require('mysql2/promise');

async function run() {
  const sql = fs.readFileSync(__dirname + '/schema.sql', 'utf8');

  const conn = await mysql.createConnection({
    host: process.env.DB_HOST || 'localhost',
    port: process.env.DB_PORT ? Number(process.env.DB_PORT) : 3306,
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASS || '',
    database: process.env.DB_NAME || undefined,
    multipleStatements: true
  });

  try {
    if (process.env.DB_NAME) {
      await conn.query(`CREATE DATABASE IF NOT EXISTS \`${process.env.DB_NAME}\`;`);
      await conn.query(`USE \`${process.env.DB_NAME}\`;`);
    }

    console.log('Running schema...');
    await conn.query(sql);
    console.log('Schema applied successfully.');
  } catch (err) {
    console.error('Migration error:', err);
    process.exit(1);
  } finally {
    await conn.end();
  }
}

run();
