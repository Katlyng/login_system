const { pool } = require("./connection.js");
const users = require("./users.js");
const roles = require("./roles.js");
const { logEvent, AUDIT_STATES } = require("./audit.js");
const userRoles = require("./users_roles.js");

const getUsers = async () => {
  try {
    const [result] = await pool.query("SELECT * FROM users");
    return result;
  } catch (error) {
    console.error("Error al obtener usuarios:", error);
    return [];
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

      await logEvent(
        user.id,
        AUDIT_STATES.USER_REGISTERED,
        `Nuevo usuario registrado: ${user.username} (${user.email})`,
        null // No hay IP disponible durante la inicialización
      );
    }
  } catch (error) {
    console.log(error);
  }
};
const initializeDatabase = async () => {
  console.log("Inicializando la base de datos...");
  await addUser();
  await getUsers();
  await addRoles();
  await getUserRoles();
  await addUserRoles();
  // await pool.end(); // Finalizar la conexión
};
const updateHashPassword = async (userId, newPasswordHash) => {
  console.log(`Actualizando contraseña para user_id: ${userId}`);
  console.log(`Nueva contraseña hasheada: ${newPasswordHash}`);
  try {
    const [result] = await pool.query(
      "UPDATE users SET hash_password = ?, update_date = NOW() WHERE user_id = ?",
      [newPasswordHash, userId]
    );
    return result.affectedRows > 0;
  } catch (error) {
    console.log("Error al actualizar la contraseña:", error);
    return false;
  }
};

async function addRoles() {
  try {
    for (const role of roles) {
      // Verificar si el rol ya existe
      const [rows] = await pool.query("SELECT * FROM roles WHERE name = ?", [
        role.name,
      ]);

      if (rows.length === 0) {
        // Insertar rol si no existe
        await pool.query("INSERT INTO roles (rol_id, name) VALUES (?,?)", [
          role.rol_id,
          role.name,
        ]);
        console.log(`Rol agregado: ${role.name}`);
      }
    }
  } catch (error) {
    console.error("Error al agregar roles:", error);
  }
}

const addUserRoles = async () => {
  try {
    console.log("Asignando roles a los usuarios...");

    for (const userRole of userRoles) {
      const { user_id, rol_id } = userRole;

      try {
        // Intentar insertar la relación usuario-rol
        await pool.query(
          "INSERT INTO users_roles (user_id, rol_id) VALUES (?, ?)",
          [user_id, rol_id]
        );
        console.log(`Rol ${rol_id} asignado al usuario ${user_id}`);
      } catch (error) {
        // Si el error es por clave duplicada (código 1062), ignorarlo y continuar
        if (error.code === "ER_DUP_ENTRY") {
          console.log(
            `El usuario ${user_id} ya tiene el rol ${rol_id}, omitiendo...`
          );
          continue;
        }
        // Si es otro error, lanzarlo
        throw error;
      }
    }

    console.log("Roles asignados correctamente.");
  } catch (error) {
    console.error("Error asignando roles a los usuarios:", error);
  }
};

const getUserRoles = async (userId) => {
  try {
    const [roles] = await pool.query(
      "SELECT r.name FROM roles r INNER JOIN users_roles ur ON r.rol_id = ur.rol_id WHERE ur.user_id = ?",
      [userId]
    );
    return roles; // Devuelve la lista de roles
  } catch (error) {
    console.error("Error al obtener los roles:", error);
    return [];
  }
};

const incrementFailedAttempts = async (userId) => {
  try {
    const [result] = await pool.query(
      "UPDATE users SET failed_try = failed_try + 1, update_date = NOW() WHERE user_id = ?",
      [userId]
    );
    return result.affectedRows > 0;
  } catch (error) {
    console.error("Error al incrementar intentos fallidos:", error);
    return false;
  }
};

const resetFailedAttempts = async (userId) => {
  try {
    const [result] = await pool.query(
      "UPDATE users SET failed_try = 0, update_date = NOW() WHERE user_id = ?",
      [userId]
    );
    return result.affectedRows > 0;
  } catch (error) {
    console.error("Error al restablecer intentos fallidos:", error);
    return false;
  }
};

const blockAccount = async (userId) => {
  try {
    const [result] = await pool.query(
      "UPDATE users SET block = 1, update_date = NOW() WHERE user_id = ?",
      [userId]
    );
    return result.affectedRows > 0;
  } catch (error) {
    console.error("Error al bloquear cuenta:", error);
    return false;
  }
};

const unlockAccount = async (userId) => {
  try {
    const [result] = await pool.query(
      "UPDATE users SET block = 0, failed_try = 0, update_date = NOW() WHERE user_id = ?",
      [userId]
    );
    return result.affectedRows > 0;
  } catch (error) {
    console.error("Error al desbloquear cuenta:", error);
    return false;
  }
};

module.exports = {
  initializeDatabase,
  updateHashPassword,
  getUserRoles,
  getUsers,
  incrementFailedAttempts,
  resetFailedAttempts,
  blockAccount,
  unlockAccount,
};
