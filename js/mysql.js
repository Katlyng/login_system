const { pool } = require("./connection.js");
const users = require("./users.js");

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
      // Verificar si el user_id ya existe
      const [existingUser] = await pool.query(
        "SELECT * FROM users WHERE user_id = ?",
        [user.id]
      );
      if (existingUser.length > 0) {
        console.log(`El usuario con ID ${user.id} ya existe.`);
        continue; // Saltar a la siguiente iteración si el usuario ya existe
      }

      // Insertar el nuevo usuario
      const [result] = await pool.query(
        "INSERT INTO users (user_id, name, email, hash_password, failed_try, block, creation_date, update_date) VALUES (?, ?, ?, ?, 0, 0, NOW(), NOW())",
        [user.id, user.username, user.email, user.password]
      );
      console.log(result);
    }
  } catch (error) {
    console.log(error);
  }
};
const initializeDatabase = async () => {
  console.log("Inicializando la base de datos...");
  await addUser();
  await getusers();
  // await pool.end(); // Finalizar la conexión
};
const updateHashPassword = async (userId, newPasswordHash) => {
  try {
    const [result] = await pool.query("UPDATE users SET hash_password = ?, update_date = NOW() WHERE user_id = ?",
      [newPasswordHash, userId]
    );
    return result.affectedRows > 0;
    
  } catch (error) {
    console.log("Error al actualizar la contraseña:", error);
    return false;
    
  }

}
module.exports = { initializeDatabase, updateHashPassword };
