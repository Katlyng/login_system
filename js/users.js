const bcrypt = require('bcrypt');

const users = [
    { id: 1, username: "admin", password: bcrypt.hashSync("123456", 10), email: "katlyn2galvis@gmail.com" }
];

module.exports = users;