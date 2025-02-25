const bcrypt = require("bcrypt");

const users = [
  {
    id: 1,
    name: "admin",
    hash_password: bcrypt.hashSync("123456", 10),
    email: "katlyn2galvis@gmail.com",
  },
  {
    id: 2,
    uname: "juan",
    hashpassword: bcrypt.hashSync("123456", 10),
    email: "juan.albornoz@uptc.edu.co",
  },
];

module.exports = users;
