const { pool } = require('./connection.js');
const bcrypt = require('bcrypt');

const users = [
    { id: 1, username: "admin", password: bcrypt.hashSync("123456", 10), email: "katlyn2galvis@gmail.com" }
];

const getusers = async () => {
  try {
    const [result] = await pool.query("SELECT * FROM users");
    console.log(result);
  } catch (error) {
    console.log(error);
  }
};
const addUser = async () => {
    try {
        for (const user of users) {
        const [result] = await pool.query(
            "INSERT INTO users (user_id, name, email, hash_password, failed_try, block, creation_date, update_date) VALUES (?, ?, ?, ?, 0, 0, NOW(), NOW())",
            [user.id, user.username, user.email, user.password]

        );
        console.log(result);
    }
    } catch (error) {
        console.log(error);
    }

}
// addUser(); 

getusers();

