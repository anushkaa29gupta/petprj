// ══════════════════════════════════════════════════════════════
//  PET-PROJECT — db.js
//  MySQL connection pool. server.js uses both db.query() directly
//  and db.getConnection() (for the AES key + audit-context calls),
//  so this must be a pool, not a single connection.
// ══════════════════════════════════════════════════════════════
require("dotenv").config();
const mysql = require("mysql2");

const pool = mysql.createPool({
  host:               process.env.DB_HOST || "localhost",
  port:               process.env.DB_PORT || 3306,
  user:               process.env.DB_USER || "root",
  password:           process.env.DB_PASSWORD || "",
  database:           process.env.DB_NAME || "petdb",
  waitForConnections: true,
  connectionLimit:    10,
  queueLimit:         0,
  multipleStatements: false,
});

pool.getConnection((err, conn) => {
  if (err) {
    console.error("❌ MySQL pool failed to connect:", err.message);
    return;
  }
  console.log("✅ MySQL pool connected to database:", process.env.DB_NAME || "petdb");
  conn.release();
});

module.exports = pool;