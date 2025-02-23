const mysql = require("mysql2/promise");

const pool = mysql.createPool({
    host: "localhost",
    port: 3306,
    database: "ls",
    user: "root",
    password: "root",
});
module.exports = { pool };
