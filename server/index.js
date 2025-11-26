require('dotenv').config();
const express = require('express');
const cors = require('cors');
const db = require('./db');

const app = express();

// Middlewares
app.use(cors());
app.use(express.json());

// Middleware de autenticación
function auth(req, res, next) {
  const header = req.headers.authorization;

  if (!header) return res.status(401).json({ error: "Falta token" });

  const token = header.split(" ")[1];

  try {
    const data = jwt.verify(token, process.env.JWT_SECRET);
    req.user = data;
    next();
  } catch (err) {
    return res.status(401).json({ error: "Token inválido" });
  }
}


app.get('/', async (req, res) => {
  try {
    const [rows] = await db.query('SELECT NOW() as now');
    res.send("API funcionando. Hora de MySQL: " + rows[0].now);
  } catch (err) {
    console.error(err);
    res.status(500).send("Error con la base de datos");
  }
});

const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');


// ----------- REGISTRO -----------------------
app.post('/api/register', async (req, res) => {
  const {
    username,
    email,
    password,
    nombre,
    apellido,
    fecha_nacimiento
  } = req.body;

  // Validaciones básicas
  if (!username || !email || !password || !nombre || !apellido || !fecha_nacimiento) {
    return res.status(400).json({ error: "Faltan campos" });
  }

  try {
    // Encriptar contraseña
    const password_hash = await bcrypt.hash(password, 10);

    // Insertar usuario
    const sql = `
      INSERT INTO users 
        (username, email, password_hash, nombre, apellido, fecha_nacimiento)
      VALUES (?, ?, ?, ?, ?, ?)
    `;

    await db.query(sql, [
      username,
      email,
      password_hash,
      nombre,
      apellido,
      fecha_nacimiento
    ]);

    return res.json({ message: "Usuario registrado correctamente" });
  } catch (err) {
    console.error(err);

    if (err.code === "ER_DUP_ENTRY") {
      return res.status(400).json({ error: "Email o username ya existen" });
    }

    return res.status(500).json({ error: "Error registrando usuario" });
  }
});


// -------------- LOGIN -----------------------
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: "Faltan campos" });
  }

  try {
    const [rows] = await db.query(
      "SELECT * FROM users WHERE email = ?",
      [email]
    );

    if (rows.length === 0) {
      return res.status(400).json({ error: "Usuario no encontrado" });
    }

    const user = rows[0];

    const isValid = await bcrypt.compare(password, user.password_hash);

    if (!isValid) {
      return res.status(401).json({ error: "Contraseña incorrecta" });
    }

    const token = jwt.sign(
      {
        id: user.id,
        username: user.username
      },
      process.env.JWT_SECRET,
      { expiresIn: "2h" }
    );

    return res.json({ token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error en el login" });
  }
});

// ------------- PERFIL ------------------------
app.get('/api/profile', auth, async (req, res) => {
  try {
    const [rows] = await db.query(
      "SELECT id, username, email, nombre, apellido, fecha_nacimiento, created_at FROM users WHERE id = ?",
      [req.user.id]
    );

    if (rows.length === 0) {
      return res.status(404).json({ error: "Usuario no encontrado" });
    }

    res.json(rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error al obtener perfil" });
  }
});


const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log("Servidor arrancado en puerto " + PORT);
});
