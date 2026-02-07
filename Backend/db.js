require('dotenv').config();
const mysql = require('mysql2/promise');

function asBool(value) {
  if (!value) return false;
  const v = String(value).trim().toLowerCase();
  return v === '1' || v === 'true' || v === 'yes' || v === 'on';
}

function parseMysqlUrl(urlString) {
  try {
    const url = new URL(urlString);
    return {
      host: url.hostname,
      port: url.port ? Number(url.port) : 3306,
      user: decodeURIComponent(url.username || ''),
      password: decodeURIComponent(url.password || ''),
      database: url.pathname ? url.pathname.replace(/^\//, '') : undefined
    };
  } catch (e) {
    return null;
  }
}

const sslEnabled = asBool(process.env.DB_SSL || process.env.MYSQL_SSL);
const sslOptions = sslEnabled ? { rejectUnauthorized: false } : undefined;

const rawUrl = process.env.DATABASE_URL || process.env.MYSQL_URL;
const urlConfig = rawUrl ? parseMysqlUrl(rawUrl) : null;

const poolConfig = urlConfig || {
  host: process.env.DB_HOST || process.env.MYSQLHOST || process.env.MYSQL_HOST || 'localhost',
  port: process.env.DB_PORT ? Number(process.env.DB_PORT)
    : (process.env.MYSQLPORT ? Number(process.env.MYSQLPORT) : 3306),
  user: process.env.DB_USER || process.env.MYSQLUSER || process.env.MYSQL_USER || 'root',
  password: process.env.DB_PASS || process.env.DB_PASSWORD || process.env.MYSQLPASSWORD || process.env.MYSQL_PASSWORD || '',
  database: process.env.DB_NAME || process.env.MYSQLDATABASE || process.env.MYSQL_DATABASE || 'cfp_db1'
};

if (sslOptions) {
  poolConfig.ssl = sslOptions;
}

const pool = mysql.createPool({
  ...poolConfig,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

module.exports = { pool };
