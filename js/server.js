require("dotenv").config(); //para cargar las variables de entorno (clase secreta JWT, recomendado incluir puertos)
const express = require("express"); //framework para crear aplicaciones web
const jwt = require("jsonwebtoken"); //para crear y verificar tokens JWT
const bcrypt = require("bcryptjs"); //para encriptar y comparar contraseñas
const cors = require("cors"); //para permitir peticiones desde otros dominios
const bodyParser = require("body-parser"); //para leer datos enviados desde el cliente y convertirlos a JSON
const nodemailer = require("nodemailer"); //para enviar correos electrónicos
const crypto = require("crypto"); //para generar tokens aleatorios

const app = express(); //inicializar la aplicación
const PORT = process.env.PORT || 3000; //puerto del servidor usando la varibale de entorno o por defecto (3000)

const users = [
    { id: 1, username: "admin", password: bcrypt.hashSync("123456", 10), email: "katlyn2galvis@gmail.com" }
];

const passwordResetTokens = []; // Lista temporal para almacenar los tokens cuando un usuario solicita restablecer su contraseña

// Configurar el servicio de correo 
const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
        user: process.env.EMAIL_USER, 
        pass: process.env.EMAIL_PASS  
    }
});

// Middleware
app.use(cors()); //permite solicitudes de otros dominios
app.use(bodyParser.json()); //para que el cuerpo de las peticiones se interprete como JSON
app.use(express.static("public")); // Para servir archivos HTML/CSS

// Ruta de login
app.post("/login", (req, res) => {
    const { username, password } = req.body; //se extraen del cuerpo de la solicitud

    // Buscar usuario (SELECT)
    const user = users.find(u => u.username === username);

    if (!user || !bcrypt.compareSync(password, user.password)) {
        return res.status(401).json({ error: "Usuario o contraseña incorrectos" });
    }

    // Crear token JWT
    const token = jwt.sign({ id: user.id, username: user.username }, process.env.JWT_SECRET, {
        expiresIn: "1h",
    });

    res.json({ message: "Login exitoso", token });
});

// Iniciar servidor
app.listen(PORT, () => console.log(`Servidor corriendo en http://localhost:${PORT}`));
