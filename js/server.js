require("dotenv").config();
const {
  logEvent,
  AUDIT_STATES,
  getClientIp,
  getUserAuditHistory,
  getAllAuditLogs,
} = require("./audit.js"); //para cargar las variables de entorno (clase secreta JWT, recomendado incluir puertos)
const express = require("express"); //framework para crear aplicaciones web
const jwt = require("jsonwebtoken"); //para crear y verificar tokens JWT
const bcrypt = require("bcryptjs"); //para encriptar y comparar contraseñas
const pool = require("./mysql");
const cors = require("cors"); //para permitir peticiones desde otros dominios
const bodyParser = require("body-parser"); //para leer datos enviados desde el cliente y convertirlos a JSON
const nodemailer = require("nodemailer"); //para enviar correos electrónicos
const crypto = require("crypto"); //para generar tokens aleatorios
const path = require("path");

const {
  initializeDatabase,
  updateHashPassword,
  getUsers,
  getUserRoles,
  incrementFailedAttempts,
  resetFailedAttempts,
  blockAccount,
  unlockAccount,
} = require("../js/mysql.js");

const app = express(); //inicializar la aplicación
const PORT = process.env.PORT || 3000; //puerto del servidor usando la varibale de entorno o por defecto (3000)
const passwordResetTokens = []; // Lista temporal para almacenar los tokens cuando un usuario solicita restablecer su contraseña

// Configurar el servicio de correo
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// Middleware
app.use(cors()); //permite solicitudes de otros dominios
app.use(bodyParser.json()); //para que el cuerpo de las peticiones se interprete como JSON
app.use(express.static("public")); // Para servir archivos HTML/CSS
// Middleware para verificar token
function verifyToken(req, res, next) {
  const token = req.headers["authorization"];

  if (!token) {
    return res.status(403).json({ error: "Token requerido" });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(401).json({ error: "Token inválido" });
    }
    req.user = decoded;
    next();
  });
}
// Middleware para verificar si un usuario tiene un rol específico
function verifyRole(requiredRole) {
  return (req, res, next) => {
    if (!req.user || !req.user.roles.includes(requiredRole)) {
      return res.status(403).json({ error: "Acceso denegado" });
    }
    next();
  };
}

app.get("/index", (req, res) => {
  res.sendFile(__dirname + "/public/index.html"); // Asegúrate de que el archivo exista
});
// Ruta de login (modificada)
app.post("/login", async (req, res) => {
  const { username, password } = req.body; //se extraen del cuerpo de la solicitud
  const clientIp = getClientIp(req);
  // Buscar usuario (SELECT)
  const usersList = await getUsers();
  console.log("Lista de usuarios obtenida:", usersList);
  const user = usersList.find((u) => u.name === username);

  if (!user) {
    await logEvent(
      null,
      AUDIT_STATES.LOGIN_FAILED,
      `Intento de inicio de sesión con usuario inexistente: ${username}`,
      clientIp
    );
    return res.status(401).json({ error: "Usuario o contraseña incorrectos" });
  }

  //verificar si la cuenta está bloqueada
  if (user.block === 1) {
    await logEvent(
      user.user_id,
      AUDIT_STATES.LOGIN_FAILED,
      "Intento de inicio de sesión en cuenta bloqueada",
      clientIp
    );
    return res.status(403).json({
      error: "Cuenta bloqueada por múltiples intentos fallidos. Revisa tu correo para desbloquearla.",
      accountBlocked: true,  // Flag para indicar que la cuenta está bloqueada
      email: user.email      // Enviar el email para facilitar la solicitud de desbloqueo
    });
  }

  // Comparar la contraseña ingresada con el hash almacenado
  const isMatch = await bcrypt.compare(password, user.hash_password);

  if (!isMatch) {
    // Incrementar contador de intentos fallidos
    await incrementFailedAttempts(user.user_id);

    //volver a obtener usuario actualizado
    const updatedUser = (await getUsers()).find(
      (u) => u.user_id === user.user_id
    );

    await logEvent(
      user.user_id,
      AUDIT_STATES.LOGIN_FAILED,
      `Contraseña incorrecta. Intento ${updatedUser.failed_try} de 5`,
      clientIp
    );

    //verificar si se alcanzó el límite de intentos
    if (updatedUser.failed_try >= 5) {
      //bloquear cuenta
      await blockAccount(user.user_id);
      //enviar correo de desbloqueo
      await sendUnlockEmail(user.email, user.user_id);
      await logEvent(
        user.user_id,
        AUDIT_STATES.ACCOUNT_BLOCKED,
        "Cuenta bloqueada por exceder número máximo de intentos fallidos",
        clientIp
      );

      return res.status(403).json({
        error: "Cuenta bloqueada por múltiples intentos fallidos. Se ha enviado un correo para desbloquearla.",
        accountBlocked: true,  // Flag para indicar que la cuenta está bloqueada
        email: user.email      // Enviar el email para facilitar la solicitud de desbloqueo
      });
    }

    return res.status(401).json({
      error: `Usuario o contraseña incorrectos. Intentos restantes: ${
        5 - updatedUser.failed_try
      }`,
    });
  } else {
    // IMPORTANTE: Verificar nuevamente si la cuenta está bloqueada antes de permitir el login
    // Obtener el usuario actualizado para verificar su estado actual
    const currentUser = (await getUsers()).find(
      (u) => u.user_id === user.user_id
    );
    
    // Si la cuenta está bloqueada, no permitir el acceso incluso con contraseña correcta
    if (currentUser.blocked === 1) {
      await logEvent(
        user.user_id,
        AUDIT_STATES.LOGIN_FAILED,
        "Intento de inicio de sesión con contraseña correcta en cuenta bloqueada",
        clientIp
      );
      return res.status(403).json({
        error: "Cuenta bloqueada por múltiples intentos fallidos. Revisa tu correo para desbloquearla.",
        accountBlocked: true,  // Flag para indicar que la cuenta está bloqueada
        email: user.email      // Enviar el email para facilitar la solicitud de desbloqueo
      });
    }
    
    // Si la contraseña es correcta y la cuenta no está bloqueada, restablecer contador de intentos fallidos
    await resetFailedAttempts(user.user_id);

    // Obtener roles del usuario
    let roleNames = [];
    try {
      const roles = await getUserRoles(user.user_id); // Obtener roles desde la BD
      console.log("Datos crudos de roles obtenidos:", roles);
      roleNames = roles.map((role) => role.name);
      console.log("Roles después de map:", roleNames);
    } catch (error) {
      console.error("Error obteniendo roles:", error);
      return res
        .status(500)
        .json({ error: "Error obteniendo roles del usuario" });
    }

    // Crear token JWT (corregido para usar user_id en lugar de id)
    const token = jwt.sign(
      { id: user.user_id, username: user.name, roles: roleNames },
      process.env.JWT_SECRET,
      {
        expiresIn: "1h",
      }
    );
    // Registrar inicio de sesión exitoso en auditoría
    await logEvent(
      user.user_id,
      AUDIT_STATES.LOGIN_SUCCESS,
      `Inicio de sesión exitoso. Usuario: ${user.name}`,
      clientIp
    );

    // Responder con el token y mensaje de éxito
    res.json({ message: "Login exitoso", token });
  }
});

// Función para enviar correo de desbloqueo (reutilizando la lógica de reset de contraseña)
async function sendUnlockEmail(email, userId) {
  // Generar token único
  const token = crypto.randomBytes(32).toString("hex");
  const expirationTime = Date.now() + 30 * 60 * 1000; // Expira en 30 minutos

  // Guardar token (mismo array)
  passwordResetTokens.push({
    token,
    userId,
    used: false,
    expires: expirationTime,
    isUnlockToken: true, // Identificar que es un token de desbloqueo
  });

  // Crear enlace para desbloqueo
  const unlockLink = `http://localhost:${PORT}/unlock-account?token=${token}`;

  // Configurar mensaje
  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: email,
    subject: "Desbloqueo de Cuenta",
    html: `
       <h2>Tu cuenta ha sido bloqueada</h2>
       <p>Debido a múltiples intentos fallidos de inicio de sesión, tu cuenta ha sido bloqueada por seguridad.</p>
       <p>Para desbloquear tu cuenta, haz clic en el siguiente enlace:</p>
       <a href="${unlockLink}">${unlockLink}</a>
       <p>Este enlace expira en 30 minutos.</p>
       <p>Si no has sido tú quien intentó acceder a la cuenta, te recomendamos cambiar tu contraseña una vez desbloquees la cuenta.</p>
     `,
  };

  // Enviar correo
  return new Promise((resolve, reject) => {
    transporter.sendMail(mailOptions, (err, info) => {
      if (err) {
        console.error("Error al enviar correo de desbloqueo:", err);
        reject(err);
      } else {
        console.log("Correo de desbloqueo enviado:", info.response);
        resolve(info);
      }
    });
  });
}

// Añadir ruta para la página de desbloqueo
app.get("/unlock-account", (req, res) => {
  res.sendFile(path.join(__dirname, "..", "public", "unlock-account.html"));
});
// Añadir ruta para procesar el desbloqueo
app.post("/unlock-account", async (req, res) => {
  const { token } = req.body;
  const clientIp = getClientIp(req);
  // Buscar el token
  const storedToken = passwordResetTokens.find(
    (t) => t.token === token && t.isUnlockToken === true
  );

  if (!storedToken) {
    return res.status(400).json({ error: "Token inválido" });
  }

  if (storedToken.used) {
    return res.status(400).json({ error: "El token ya ha sido usado" });
  }

  if (Date.now() > storedToken.expires) {
    return res.status(400).json({ error: "El token ha expirado" });
  }

  try {
    // Desbloquear la cuenta
    const unlocked = await unlockAccount(storedToken.userId);

    if (!unlocked) {
      return res.status(500).json({ error: "Error al desbloquear la cuenta" });
    }

    // Marcar el token como usado
    storedToken.used = true;

    // Registrar desbloqueo en auditoría
    await logEvent(
      storedToken.userId,
      AUDIT_STATES.ACCOUNT_UNLOCKED,
      "Cuenta desbloqueada mediante token enviado por correo",
      clientIp
    );

    res.json({
      message: "Cuenta desbloqueada correctamente. Ya puedes iniciar sesión.",
    });
  } catch (error) {
    console.error("Error al desbloquear cuenta:", error);
    res.status(500).json({ error: "Error al desbloquear la cuenta" });
  }
});

// Ruta protegida para administradores
app.get("/admin", verifyToken, verifyRole("admin"), (req, res) => {});
// Ruta protegida para ver logs de auditoría (solo admin)
app.get("/audit-logs", verifyToken, verifyRole("admin"), async (req, res) => {
  try {
    const { limit = 100, offset = 0, userId } = req.query;

    let auditLogs;
    if (userId) {
      // Si se proporciona un userId, filtrar por ese usuario
      auditLogs = await getUserAuditHistory(userId);
    } else {
      // Si no, obtener todos los logs (con paginación)
      auditLogs = await getAllAuditLogs(parseInt(limit), parseInt(offset));
    }

    res.json({
      total: auditLogs.length,
      data: auditLogs,
    });
  } catch (error) {
    console.error("Error al obtener logs de auditoría:", error);
    res
      .status(500)
      .json({ error: "Error al consultar los registros de auditoría" });
  }
});

// Ruta de forgot-password
app.post("/forgot-password", async (req, res) => {
  const { email } = req.body;
  const clientIp = getClientIp(req);
  const usersList = await getUsers();
  const user = usersList.find((u) => u.email === email);

  if (!user) {
    return res.status(404).json({ error: "Correo no encontrado" });
  }

  // Generar un token único
  const token = crypto.randomBytes(32).toString("hex");
  const expirationTime = Date.now() + 10 * 60 * 1000; // Expira en 15 min

  // Guardar el token en la lista temporal
  passwordResetTokens.push({
    token,
    userId: user.user_id,
    used: false,
    expires: expirationTime,
  });
  await logEvent(
    user.user_id,
    AUDIT_STATES.PASSWORD_RESET_REQUEST,
    "Solicitud de restablecimiento de contraseña",
    clientIp
  );

  // Enviar correo con el enlace de recuperación
  const resetLink = `http://localhost:3000/reset-password?token=${token}`;
  const mailOptions = {
    from: "tu_correo@gmail.com",
    to: email,
    subject: "Recuperación de Contraseña",
    html: `<p>Haz clic en el siguiente enlace para restablecer tu contraseña:</p>
               <a href="${resetLink}">${resetLink}</a>
               <p>Este enlace expira en 10 minutos.</p>`,
  };

  transporter.sendMail(mailOptions, (err, info) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: "Error al enviar el correo" });
    }
    res.json({ message: "Correo enviado, revisa tu bandeja de entrada" });
  });
});

app.get("/reset-password", (req, res) => {
  res.sendFile(path.join(__dirname, "..", "public", "reset-password.html"));
});
app.post("/reset-password", async (req, res) => {
  const { token, newPassword } = req.body;
  const clientIp = getClientIp(req);
  // Buscar el token
  const storedToken = passwordResetTokens.find((t) => t.token === token);

  if (!storedToken) {
    return res.status(400).json({ error: "Token inválido" });
  }

  if (storedToken.used) {
    return res.status(400).json({ error: "El token ya ha sido usado" });
  }

  if (Date.now() > storedToken.expires) {
    return res.status(400).json({ error: "El token ha expirado" });
  }

  // Buscar el usuario
  const usersList = await getUsers();
  const user = usersList.find((u) => u.user_id === storedToken.userId);
  if (!user) {
    return res.status(404).json({ error: "Usuario no encontrado" });
  }

  // Actualizar la contraseña

  try {
    // Actualizar en la base de datos
    const hashedPassword = bcrypt.hashSync(newPassword, 10);
    const passwordUpdateddb = await updateHashPassword(
      user.user_id,
      hashedPassword
    );
    console.log("Contraseña actualizada en la BD:", passwordUpdateddb);

    // Marcar el token como usado
    storedToken.used = true;

    await logEvent(
      user.user_id,
      AUDIT_STATES.PASSWORD_RESET_SUCCESS,
      "Contraseña restablecida exitosamente",
      clientIp
    );

    res.json({ message: "Contraseña actualizada correctamente" });
  } catch (error) {
    console.error("Error al actualizar la contraseña:", error);
    res.status(500).json({ error: "Error al actualizar la contraseña" });
  }
});

// Añadir una página HTML para solicitar desbloqueo de cuenta
app.get("/request-unlock", (req, res) => {
  res.sendFile(path.join(__dirname, "..", "public", "request-unlock.html"));
});
// Ruta para solicitar un nuevo token de desbloqueo
app.post("/request-unlock", async (req, res) => {
  const { email } = req.body;
  const clientIp = getClientIp(req);
  
  // Buscar usuario por email
  const usersList = await getUsers();
  const user = usersList.find((u) => u.email === email);

  if (!user) {
    // No revelar si el email existe o no por seguridad
    return res.json({ 
      message: "Si el correo existe y la cuenta está bloqueada, recibirás instrucciones para desbloquearla" 
    });
  }

  // Verificar si la cuenta está realmente bloqueada
  if (user.block !== 1) {
    // Si la cuenta no está bloqueada, informar al usuario pero sin revelar detalles
    return res.json({ 
      message: "Si el correo existe y la cuenta está bloqueada, recibirás instrucciones para desbloquearla" 
    });
  }

  // Generar y enviar un nuevo token de desbloqueo
  try {
    await sendUnlockEmail(user.email, user.user_id);
    
    await logEvent(
      user.user_id,
      AUDIT_STATES.UNLOCK_TOKEN_REQUESTED,
      "Nuevo token de desbloqueo solicitado",
      clientIp
    );

    res.json({ 
      message: "Si el correo existe y la cuenta está bloqueada, recibirás instrucciones para desbloquearla" 
    });
  }
  catch (error) {
    console.error("Error al solicitar desbloqueo:", error);
    res.status(500).json({ error: "Error al solicitar desbloqueo de cuenta" });
  }
});

// Ruta protegida para ver logs de auditoría (solo admin)
app.get("/audit-logs", verifyToken, verifyRole("admin"), async (req, res) => {
  try {
    const { limit = 100, offset = 0, userId, state} = req.query;

    // Obtener todos los logs primero
    let auditLogs;
    if (userId) {
      // Si se proporciona un userId, filtrar por ese usuario
      auditLogs = await getUserAuditHistory(userId);
    } else {
      // Si no, obtener todos los logs (con paginación)
      auditLogs = await getAllAuditLogs(parseInt(limit), parseInt(offset));
    }

    // Aplicar filtro de estado si se proporciona
    if (state) {
      auditLogs = auditLogs.filter((log) => log.state === state);
    }

    res.json({
      total: auditLogs.length,
      data: auditLogs,
    });
  } catch (error) {
    console.error("Error al enviar correo de desbloqueo:", error);
    res.status(500).json({ error: "Error al procesar la solicitud" });
  }
});

// Iniciar servidor
initializeDatabase().finally(() => {
  app.listen(PORT, () => {
    console.log(` Servidor corriendo en http://localhost:${PORT}`);
  });
});