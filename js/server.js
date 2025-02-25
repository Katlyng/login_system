require("dotenv").config(); //para cargar las variables de entorno (clase secreta JWT, recomendado incluir puertos)
const express = require("express"); //framework para crear aplicaciones web
const jwt = require("jsonwebtoken"); //para crear y verificar tokens JWT
const bcrypt = require("bcryptjs"); //para encriptar y comparar contraseñas
const pool = require("./mysql");
const cors = require("cors"); //para permitir peticiones desde otros dominios
const bodyParser = require("body-parser"); //para leer datos enviados desde el cliente y convertirlos a JSON
const nodemailer = require("nodemailer"); //para enviar correos electrónicos
const crypto = require("crypto"); //para generar tokens aleatorios
const path = require("path");
const { initializeDatabase } = require("../js/mysql.js");
const { updateHashPassword } = require("../js/mysql.js");
const { getUsers } = require("../js/mysql.js");

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

app.get("/index", (req, res) => {
  res.sendFile(__dirname + "/public/index.html"); // Asegúrate de que el archivo exista
});

// Ruta de login
app.post("/login", async (req, res) => {
  const { username, password } = req.body; //se extraen del cuerpo de la solicitud

  // Buscar usuario (SELECT)
  const usersList = await getUsers();
  console.log("Lista de usuarios obtenida:", usersList);
  const user = usersList.find((u) => u.name === username);

  if (!user) {
    
    return res.status(401).json({ error: "Usuario o contraseña incorrectos" });
  }

// Obtener roles del usuario
let roleNames = [];
if (user) {
    try {
        const roles = await getUserRoles(user.user_id); // Obtener roles desde la BD
        console.log("Datos crudos de roles obtenidos:", roles);
        roleNames = roles.map(role => role.name);
        console.log("Roles después de map:", roleNames);
    } catch (error) {
        console.error("Error obteniendo roles:", error);
        return res.status(500).json({ error: "Error obteniendo roles del usuario" });
    }
}
// Comparar la contraseña ingresada con el hash almacenado
const isMatch = await bcrypt.compare(password, user.hash_password);

if (!isMatch) {
  
  return res.status(401).json({ error: "Usuario o contraseña incorrectos" })
  ;
}
  // Crear token JWT
  const token = jwt.sign(
    { id: user.id, username: user.name, roles: roleNames },
  
  process.env.JWT_SECRET,
    {
      expiresIn: "1h",
    }
  );
  res.json({ message: "Login exitoso", token });
});

// Middleware para verificar si un usuario tiene un rol específico
function verifyRole(requiredRole) {
    return (req, res, next) => {
        if (!req.user || !req.user.roles.includes(requiredRole)) {
            return res.status(403).json({ error: "Acceso denegado" });
        }
        next();
    };
}

// Ruta protegida para administradores
app.get("/admin", verifyToken, verifyRole("admin"), (req, res) => {
    res.json({ message: "Bienvenido al panel de administrador" });
});

// Ruta de forgot-password
app.post("/forgot-password", async (req, res) => {
  const { email } = req.body;
  const usersList = await getUsers();
  const user = usersList.find((u) => u.email === email);

  if (!user) {
    return res.status(404).json({ error: "Correo no encontrado" });
  }

  // Generar un token único
  const token = crypto.randomBytes(32).toString("hex");
  const expirationTime = Date.now() + 15 * 60 * 1000; // Expira en 15 min

  // Guardar el token en la lista temporal
  passwordResetTokens.push({
    token,
    userId: user.user_id,
    used: false,
    expires: expirationTime,
  });

  // Enviar correo con el enlace de recuperación
  const resetLink = `http://localhost:3000/reset-password?token=${token}`;
  const mailOptions = {
    from: "tu_correo@gmail.com",
    to: email,
    subject: "Recuperación de Contraseña",
    html: `<p>Haz clic en el siguiente enlace para restablecer tu contraseña:</p>
               <a href="${resetLink}">${resetLink}</a>
               <p>Este enlace expira en 15 minutos.</p>`,
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
    const passwordUpdateddb = await updateHashPassword(user.user_id, hashedPassword);   
     console.log("Contraseña actualizada en la BD:", passwordUpdateddb);

    // Marcar el token como usado
    storedToken.used = true;

    res.json({ message: "Contraseña actualizada correctamente" });
  } catch (error) {
    console.error("Error al actualizar la contraseña:", error);
    res.status(500).json({ error: "Error al actualizar la contraseña" });
  }
});

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

// Iniciar servidor
initializeDatabase().finally(() => {
  app.listen(PORT, () => {
    console.log(` Servidor corriendo en http://localhost:${PORT}`);
  });
});
