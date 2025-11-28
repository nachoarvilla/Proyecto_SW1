require('dotenv').config();
const express = require('express');
const cors = require('cors');
const db = require('./db');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

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

// Ruta de prueba
app.get('/', async (req, res) => {
  try {
    const [rows] = await db.query('SELECT NOW() as now');
    res.send("API funcionando. Hora de MySQL: " + rows[0].now);
  } catch (err) {
    console.error(err);
    res.status(500).send("Error con la base de datos");
  }
});

// ----------- REGISTRO -----------------------
app.post('/api/register', async (req, res) => {
  const {
    username,
    email,
    password,
    nombre,
    apellido,
    fecha_nacimiento,
    edad,
    foto_perfil,
    grado,
    curso,
    pais,
    ciudad
  } = req.body;

  // Validaciones básicas obligatorias
  if (!username || !email || !password || !nombre || !apellido || !fecha_nacimiento) {
    return res.status(400).json({ error: "Faltan campos obligatorios" });
  }

  try {
    const password_hash = await bcrypt.hash(password, 10);

    const sql = `
      INSERT INTO users
        (username, email, password_hash, nombre, apellido, fecha_nacimiento,
         edad, foto_perfil, grado, curso, pais, ciudad)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `;

    await db.query(sql, [
      username,
      email,
      password_hash,
      nombre,
      apellido,
      fecha_nacimiento,
      edad || null,
      foto_perfil || null,
      grado || null,
      curso || null,
      pais || null,
      ciudad || null
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
    const [rows] = await db.query("SELECT * FROM users WHERE email = ?", [email]);

    if (rows.length === 0) return res.status(400).json({ error: "Usuario no encontrado" });

    const user = rows[0];

    const isValid = await bcrypt.compare(password, user.password_hash);

    if (!isValid) return res.status(401).json({ error: "Contraseña incorrecta" });

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
      `SELECT id, username, email, nombre, apellido, fecha_nacimiento, edad,
              foto_perfil, grado, curso, pais, ciudad, created_at
       FROM users
       WHERE id = ?`,
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

// ------------- PUBLICACIONES: crear ------------------------
app.post('/api/publicaciones', auth, async (req, res) => {
  const { foto, texto, ubicacion } = req.body;

  if (!foto) {
    return res.status(400).json({ error: "La foto es obligatoria" });
  }

  try {
    const sql = `
      INSERT INTO publicaciones
        (user_id, foto, texto, ubicacion)
      VALUES (?, ?, ?, ?)
    `;

    const [result] = await db.query(sql, [
      req.user.id,
      foto,
      texto || null,
      ubicacion || null
    ]);

    return res.status(201).json({
      message: "Publicación creada correctamente",
      id: result.insertId
    });

  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Error creando publicación" });
  }
});

// ------------- PUBLICACIONES: listar recientes ------------------------
app.get('/api/publicaciones', auth, async (req, res) => {
  try {
    const limit = parseInt(req.query.limit, 10) || 20;

    const [rows] = await db.query(
      `SELECT 
         p.id,
         p.foto,
         p.texto,
         p.ubicacion,
         p.fecha_creacion,
         p.likes_count,
         p.comments_count,
         u.username,
         u.foto_perfil
       FROM publicaciones p
       JOIN users u ON p.user_id = u.id
       ORDER BY p.fecha_creacion DESC
       LIMIT ?`,
      [limit]
    );

    res.json(rows);

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error al obtener publicaciones" });
  }
});

// ------------- COMENTARIOS: crear comentario en una publicación --------
app.post('/api/publicaciones/:id/comentarios', auth, async (req, res) => {
  const publicacionId = req.params.id;
  const { texto } = req.body;

  if (!texto) {
    return res.status(400).json({ error: "El texto del comentario es obligatorio" });
  }

  try {
    // Comprobar que la publicación existe
    const [pubRows] = await db.query(
      "SELECT id FROM publicaciones WHERE id = ?",
      [publicacionId]
    );

    if (pubRows.length === 0) {
      return res.status(404).json({ error: "Publicación no encontrada" });
    }

    // Insertar comentario
    const insertSql = `
      INSERT INTO comentarios
        (publicacion_id, user_id, texto)
      VALUES (?, ?, ?)
    `;

    const [result] = await db.query(insertSql, [
      publicacionId,
      req.user.id,
      texto
    ]);

    // Actualizar contador de comentarios en publicaciones
    await db.query(
      "UPDATE publicaciones SET comments_count = comments_count + 1 WHERE id = ?",
      [publicacionId]
    );

    return res.status(201).json({
      message: "Comentario creado correctamente",
      id: result.insertId
    });

  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Error creando comentario" });
  }
});

// ------------- COMENTARIOS: listar comentarios de una publicación ------
app.get('/api/publicaciones/:id/comentarios', auth, async (req, res) => {
  const publicacionId = req.params.id;

  try {
    const [rows] = await db.query(
      `SELECT 
         c.id,
         c.texto,
         c.fecha_creacion,
         c.likes_count,
         u.username,
         u.foto_perfil
       FROM comentarios c
       JOIN users u ON c.user_id = u.id
       WHERE c.publicacion_id = ?
       ORDER BY c.fecha_creacion ASC`,
      [publicacionId]
    );

    res.json(rows);

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error al obtener comentarios" });
  }
});

// ------------- TIENDA ESCOLAR: crear producto --------------------------
app.post('/api/tienda-escolar', auth, async (req, res) => {
  const { foto, descripcion, ubicacion, precio } = req.body;

  if (!foto || precio == null) {
    return res.status(400).json({ error: "Foto y precio son obligatorios" });
  }

  try {
    const sql = `
      INSERT INTO tienda_escolar
        (user_id, foto, descripcion, ubicacion, precio)
      VALUES (?, ?, ?, ?, ?)
    `;

    const [result] = await db.query(sql, [
      req.user.id,
      foto,
      descripcion || null,
      ubicacion || null,
      precio
    ]);

    return res.status(201).json({
      message: "Producto creado correctamente",
      id: result.insertId
    });

  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Error creando producto" });
  }
});

// ------------- TIENDA ESCOLAR: listar productos ------------------------
app.get('/api/tienda-escolar', auth, async (req, res) => {
  try {
    const limit = parseInt(req.query.limit, 10) || 20;

    const [rows] = await db.query(
      `SELECT 
         t.id,
         t.foto,
         t.descripcion,
         t.ubicacion,
         t.fecha_creacion,
         t.likes_count,
         t.ofertas_count,
         t.precio,
         u.username,
         u.foto_perfil
       FROM tienda_escolar t
       JOIN users u ON t.user_id = u.id
       ORDER BY t.fecha_creacion DESC
       LIMIT ?`,
      [limit]
    );

    res.json(rows);

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error al obtener productos de la tienda escolar" });
  }
});

// ------------- TIENDA ESCOLAR: crear oferta ----------------------------
app.post('/api/tienda-escolar/:id/ofertas', auth, async (req, res) => {
  const productoId = req.params.id;
  const { cantidad } = req.body;

  if (cantidad == null) {
    return res.status(400).json({ error: "La cantidad de la oferta es obligatoria" });
  }

  try {
    // Comprobar que el producto existe
    const [prodRows] = await db.query(
      "SELECT id FROM tienda_escolar WHERE id = ?",
      [productoId]
    );

    if (prodRows.length === 0) {
      return res.status(404).json({ error: "Producto no encontrado" });
    }

    // Insertar oferta
    const insertSql = `
      INSERT INTO ofertas_tienda_escolar
        (producto_id, comprador_id, cantidad)
      VALUES (?, ?, ?)
    `;

    const [result] = await db.query(insertSql, [
      productoId,
      req.user.id,
      cantidad
    ]);

    // Actualizar contador de ofertas
    await db.query(
      "UPDATE tienda_escolar SET ofertas_count = ofertas_count + 1 WHERE id = ?",
      [productoId]
    );

    return res.status(201).json({
      message: "Oferta creada correctamente",
      id: result.insertId
    });

  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Error creando oferta" });
  }
});

// ------------- TIENDA ESCOLAR: listar ofertas de un producto -----------
app.get('/api/tienda-escolar/:id/ofertas', auth, async (req, res) => {
  const productoId = req.params.id;

  try {
    const [rows] = await db.query(
      `SELECT 
         o.id,
         o.cantidad,
         o.fecha_creacion,
         u.username AS comprador,
         u.foto_perfil AS comprador_foto
       FROM ofertas_tienda_escolar o
       JOIN users u ON o.comprador_id = u.id
       WHERE o.producto_id = ?
       ORDER BY o.fecha_creacion DESC`,
      [productoId]
    );

    res.json(rows);

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error al obtener ofertas" });
  }
});

// ------------- TIENDA EXTRAESCOLAR: crear producto --------------------------
app.post('/api/tienda-extraescolar', auth, async (req, res) => {
  const { foto, descripcion, ubicacion, precio } = req.body;

  if (!foto || precio == null) {
    return res.status(400).json({ error: "Foto y precio son obligatorios" });
  }

  try {
    const sql = `
      INSERT INTO tienda_extraescolar
        (user_id, foto, descripcion, ubicacion, precio)
      VALUES (?, ?, ?, ?, ?)
    `;

    const [result] = await db.query(sql, [
      req.user.id,
      foto,
      descripcion || null,
      ubicacion || null,
      precio
    ]);

    return res.status(201).json({
      message: "Producto extraescolar creado correctamente",
      id: result.insertId
    });

  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Error creando producto extraescolar" });
  }
});

// ------------- TIENDA EXTRAESCOLAR: listar productos ------------------------
app.get('/api/tienda-extraescolar', auth, async (req, res) => {
  try {
    const limit = parseInt(req.query.limit, 10) || 20;

    const [rows] = await db.query(
      `SELECT 
         t.id,
         t.foto,
         t.descripcion,
         t.ubicacion,
         t.fecha_creacion,
         t.likes_count,
         t.ofertas_count,
         t.precio,
         u.username,
         u.foto_perfil
       FROM tienda_extraescolar t
       JOIN users u ON t.user_id = u.id
       ORDER BY t.fecha_creacion DESC
       LIMIT ?`,
      [limit]
    );

    res.json(rows);

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error al obtener productos de tienda extraescolar" });
  }
});

// ------------- TIENDA EXTRAESCOLAR: crear oferta ----------------------------
app.post('/api/tienda-extraescolar/:id/ofertas', auth, async (req, res) => {
  const productoId = req.params.id;
  const { cantidad } = req.body;

  if (cantidad == null) {
    return res.status(400).json({ error: "La cantidad de la oferta es obligatoria" });
  }

  try {
    // Comprobar que el producto existe
    const [prodRows] = await db.query(
      "SELECT id FROM tienda_extraescolar WHERE id = ?",
      [productoId]
    );

    if (prodRows.length === 0) {
      return res.status(404).json({ error: "Producto extraescolar no encontrado" });
    }

    // Insertar oferta
    const insertSql = `
      INSERT INTO ofertas_tienda_extraescolar
        (producto_id, comprador_id, cantidad)
      VALUES (?, ?, ?)
    `;

    const [result] = await db.query(insertSql, [
      productoId,
      req.user.id,
      cantidad
    ]);

    // Actualizar contador de ofertas
    await db.query(
      "UPDATE tienda_extraescolar SET ofertas_count = ofertas_count + 1 WHERE id = ?",
      [productoId]
    );

    return res.status(201).json({
      message: "Oferta extraescolar creada correctamente",
      id: result.insertId
    });

  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Error creando oferta extraescolar" });
  }
});

// ------------- TIENDA EXTRAESCOLAR: listar ofertas --------------------------
app.get('/api/tienda-extraescolar/:id/ofertas', auth, async (req, res) => {
  const productoId = req.params.id;

  try {
    const [rows] = await db.query(
      `SELECT 
         o.id,
         o.cantidad,
         o.fecha_creacion,
         u.username AS comprador,
         u.foto_perfil AS comprador_foto
       FROM ofertas_tienda_extraescolar o
       JOIN users u ON o.comprador_id = u.id
       WHERE o.producto_id = ?
       ORDER BY o.fecha_creacion DESC`,
      [productoId]
    );

    res.json(rows);

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error al obtener ofertas extraescolares" });
  }
});


// Lanzar servidor
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log("Servidor arrancado en el puerto " + PORT);
});
