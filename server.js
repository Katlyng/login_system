// BACKEND

//Importación de módulos
const express = require("express"); //Crea el servidor web
const session = require("express-session"); // Middleware que maneja sesiones en el servidor
const path = require("path"); // Módulo que maneja las rutas de archivo

//Config. del servidor
const app = express(); 
const PORT = 3000;

// Configuración de sesión
app.use(
  session({
    secret: "secreto", //Firma la sesión
    resave: false, //Evite que se guarde la sesión si no ha sido modificada
    saveUninitialized: true, //Guarda sesiones nuevas aunque no esten modificadas
  })
);

// Middleware para manejar datos de formulario
app.use(express.urlencoded({ extended: true })); 

// Servir archivos estáticos como html
app.use(express.static(path.join(__dirname)));

// Credenciales quemadas
const userData = {
  username: "admin",
  password: "12345",
};

// Ruta para la página de login
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

// Manejo del login
app.post("/login", (req, res) => {
  const { username, password } = req.body;

  if (username === userData.username && password === userData.password) {
    req.session.user = username;
    //Si está correcta la info, redijire a la página de éxito
    res.redirect("/success"); 
  } else {
    //Si no está correcta la info, envía una alerta
    res.send("<script>alert('Credenciales incorrectas'); window.location='/';</script>"); 7
    
  }
});

// Página de éxito después del login
app.get("/success", (req, res) => {
  if (req.session.user) {
    res.sendFile(path.join(__dirname, "success.html"));
  } else {
    res.redirect("/");
  }
});

// Cerrar sesión
app.get("/logout", (req, res) => {
  req.session.destroy(() => {
    res.redirect("/");
  });
});

// Iniciar servidor
app.listen(PORT, () => {
  console.log(`Servidor corriendo en http://localhost:${PORT}`);
});
