const mysql = require("mysql2");

const db = mysql.createPool({
  host: "localhost",
  user: "root",
  password: "Anushka@29gupta",
  database: "petdb",
  waitForConnections: true,
  connectionLimit: 10,
});

db.getConnection((err, connection) => {
  if (err) {
    console.log("Database Error ❌", err.message);
  } else {
    console.log("MySQL Connected ✅");
    connection.release();
  }
});

module.exports = db;