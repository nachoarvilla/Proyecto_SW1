// index.js (CÓDIGO COMPLETO Y ACTUALIZADO CON SOCKET.IO)

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const db = require('./db'); // pool de mysql2/promise
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

// 💡 CAMBIO: Importar HTTP y Socket.io
const http = require('http');
const { Server } = require('socket.io');

const app = express();
// 💡 CAMBIO: Crear servidor HTTP a partir de la app Express
const server = http.createServer(app); 

// Middlewares
app.use(cors());
app.use(express.json());

// Middleware de autenticación (Se mantiene)
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
// Middleware de autenticación de admin (Se mantiene)
function isAdmin(req, res, next) {
  if (req.user.role !== "admin") {
    return res.status(403).json({ error: "No tienes permisos de administrador." });
  }
  next();
}

module.exports = isAdmin;


//funciones propias al admin

// ADMIN: listar usuarios
app.get('/api/admin/users', auth, isAdmin, async (req, res) => {
  try {
    const search = req.query.search || "";
    const [rows] = await db.query(
      `SELECT id, username, email, nombre, apellido, created_at, role
       FROM users
       WHERE username LIKE ? OR email LIKE ?
       ORDER BY created_at DESC`,
      [`%${search}%`, `%${search}%`]
    );
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error obteniendo usuarios" });
  }
});

// ADMIN: eliminar cualquier usuario
app.delete('/api/admin/users/:id', auth, isAdmin, async (req, res) => {
  const userId = req.params.id;

  try {
    const [result] = await db.query(
      "DELETE FROM users WHERE id = ?",
      [userId]
    );

    if (result.affectedRows === 0)
      return res.status(404).json({ error: "Usuario no encontrado" });

    res.json({ message: "Usuario eliminado por administrador" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error eliminando usuario" });
  }
});

// ADMIN: cambiar rol de un usuario
app.put('/api/admin/users/:id/role', auth, isAdmin, async (req, res) => {
  const userId = req.params.id;
  const { role } = req.body;

  if (!['admin', 'user'].includes(role))
    return res.status(400).json({ error: "Rol inválido" });

  try {
    const [result] = await db.query(
      "UPDATE users SET role = ? WHERE id = ?",
      [role, userId]
    );

    res.json({ message: "Rol actualizado correctamente" });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error actualizando rol" });
  }
});

// ADMIN: listar todas las publicaciones
app.get('/api/admin/publicaciones', auth, isAdmin, async (req, res) => {
  try {
    const [rows] = await db.query(
      `SELECT p.id, p.foto, p.texto, p.fecha_creacion, u.username
       FROM publicaciones p
       JOIN users u ON p.user_id = u.id
       ORDER BY p.fecha_creacion DESC`
    );
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: "Error obteniendo publicaciones" });
  }
});

// ADMIN: eliminar publicación
app.delete('/api/admin/publicaciones/:id', auth, isAdmin, async (req, res) => {
  const pubId = req.params.id;

  try {
    const [result] = await db.query(
      "DELETE FROM publicaciones WHERE id = ?",
      [pubId]
    );

    if (!result.affectedRows)
      return res.status(404).json({ error: "Publicación no encontrada" });

    res.json({ message: "Publicación eliminada" });

  } catch (err) {
    res.status(500).json({ error: "Error eliminando publicación" });
  }
});

// ADMIN: listar productos escolares + extraescolares
app.get('/api/admin/productos', auth, isAdmin, async (req, res) => {
  try {
    const [escolar] = await db.query(
      `SELECT id, descripcion, precio, user_id, 'escolar' AS tipo FROM tienda_escolar`
    );
    const [extra] = await db.query(
      `SELECT id, descripcion, precio, user_id, 'extraescolar' AS tipo FROM tienda_extraescolar`
    );

    res.json([...escolar, ...extra]);
  } catch (err) {
    res.status(500).json({ error: "Error obteniendo productos" });
  }
});


// ADMIN: eliminar producto escolar
app.delete('/api/admin/tienda-escolar/:id', auth, isAdmin, async (req, res) => {
  const id = req.params.id;

  try {
    await db.query("DELETE FROM tienda_escolar WHERE id = ?", [id]);
    res.json({ message: "Producto escolar eliminado" });
  } catch (err) {
    res.status(500).json({ error: "Error eliminando producto escolar" });
  }
});

// ADMIN: eliminar producto extraescolar
app.delete('/api/admin/tienda-extraescolar/:id', auth, isAdmin, async (req, res) => {
  const id = req.params.id;

  try {
    await db.query("DELETE FROM tienda_extraescolar WHERE id = ?", [id]);
    res.json({ message: "Producto extraescolar eliminado" });
  } catch (err) {
    res.status(500).json({ error: "Error eliminando producto extraescolar" });
  }
});


// ADMIN: ver el dashboard de la plataforma
app.get('/api/admin/stats', auth, isAdmin, async (req, res) => {
  try {
    const [[{ totalUsuarios }]] = await db.query("SELECT COUNT(*) AS totalUsuarios FROM users");
    const [[{ totalPublicaciones }]] = await db.query("SELECT COUNT(*) AS totalPublicaciones FROM publicaciones");
    const [[{ totalChats }]] = await db.query("SELECT COUNT(*) AS totalChats FROM chats");

    res.json({
      usuarios: totalUsuarios,
      publicaciones: totalPublicaciones,
      chats: totalChats,
    });

  } catch (err) {
    res.status(500).json({ error: "Error obteniendo estadísticas" });
  }
});


//ADMIN : otras funciones del dashboard
// Estadísticas extendidas (usuarios por día, productos por tipo, top usuarios con más productos)
app.get("/api/admin/stats/extended", auth, isAdmin, async (req, res) => {
  try {

    // Nuevos usuarios por día (últimos 7 días)
    const [usuariosPorDia] = await db.query(`
      SELECT DATE(created_at) AS fecha, COUNT(*) AS total
      FROM users
      WHERE created_at >= CURDATE() - INTERVAL 6 DAY
      GROUP BY DATE(created_at)
      ORDER BY fecha ASC
    `);

    // Productos por categoría (tienda_escolar / tienda_extraescolar)
    const [prodEscolar] = await db.query(`
      SELECT 'escolar' AS tipo, COUNT(*) AS total
      FROM tienda_escolar
    `);

    const [prodExtraescolar] = await db.query(`
      SELECT 'extraescolar' AS tipo, COUNT(*) AS total
      FROM tienda_extraescolar
    `);

    const productosPorTipo = [
      { tipo: 'escolar', total: prodEscolar[0]?.total || 0 },
      { tipo: 'extraescolar', total: prodExtraescolar[0]?.total || 0 }
    ];


    // Top usuarios con más productos publicados (sumando escolar + extraescolar)
    const [topUsuariosProductos] = await db.query(`
      SELECT u.username, COALESCE(t.total, 0) AS total
      FROM users u
      LEFT JOIN (
          SELECT user_id, SUM(cnt) AS total FROM (
              SELECT user_id, COUNT(*) AS cnt FROM tienda_escolar GROUP BY user_id
              UNION ALL
              SELECT user_id, COUNT(*) AS cnt FROM tienda_extraescolar GROUP BY user_id
          ) AS x
          GROUP BY user_id
      ) t ON t.user_id = u.id
      WHERE COALESCE(t.total, 0) > 0
      ORDER BY t.total DESC
      LIMIT 5
    `);

    res.json({
      usuariosPorDia,
      productosPorTipo,
      topUsuariosProductos
    });

  } catch (err) {
    console.error("Error en estadísticas extendidas:", err);
    res.status(500).json({ error: "Error generando estadísticas extendidas" });
  }
});


// Helper: comprobar si un usuario pertenece a un chat (Se mantiene)
async function userIsMemberOfChat(chatId, userId) {
  const [rows] = await db.query(
    "SELECT 1 FROM chat_miembros WHERE chat_id = ? AND user_id = ?",
    [chatId, userId]
  );
  return rows.length > 0;
}

// -----------------------------------------------------
// 💡 IMPLEMENTACIÓN DE SOCKET.IO
// -----------------------------------------------------

// Inicializar Socket.io con la configuración CORS para tu frontend
const io = new Server(server, {
    cors: {
        origin: ["https://conoceu.vercel.app", "http://localhost:8080"], // Añade tu dominio de Vercel y localhost para desarrollo
        methods: ["GET", "POST"]
    }
});

// Middleware para autenticar la conexión de Socket.io (usando el token JWT)
io.use((socket, next) => {
    // El token se envía desde el cliente en la opción 'auth' del handshake
    const token = socket.handshake.auth.token;

    if (!token) {
        return next(new Error("Falta token de autenticación en el socket"));
    }

    try {
        const data = jwt.verify(token, process.env.JWT_SECRET);
        socket.user = data; // Adjuntar datos del usuario al socket
        next();
    } catch (err) {
        return next(new Error("Token inválido en el socket"));
    }
});

// Lógica de Sockets
io.on('connection', (socket) => {
    console.log(`Usuario conectado por socket: ${socket.user.username} (ID: ${socket.user.id})`);
    
    // Evento para que el usuario se una a la "sala" del chat
    socket.on('chat:join', (chatId) => {
        // Abandonar salas anteriores para evitar recibir mensajes de chats no activos
        Object.keys(socket.rooms).forEach(room => {
            if (room !== socket.id) { // No abandonar la sala propia de socket
                socket.leave(room);
            }
        });

        const roomName = `chat-${chatId}`;
        socket.join(roomName);
        console.log(`Usuario ${socket.user.username} se unió a la sala ${roomName}`);
    });

    // Evento de desconexión
    socket.on('disconnect', () => {
        console.log(`Usuario desconectado por socket: ${socket.user.username}`);
    });
});

// -----------------------------------------------------
// RUTAS REST API
// -----------------------------------------------------

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
    // Nota: Si has añadido 'intereses' a la tabla, debes desestructurarlo aquí
  } = req.body;

  // Validaciones básicas obligatorias
  if (!username || !email || !password || !nombre || !apellido || !fecha_nacimiento) {
    return res.status(400).json({ error: "Faltan campos obligatorios" });
  }

  try {
    const password_hash = await bcrypt.hash(password, 10);

    // Los 13 campos de la consulta: username, email, password_hash, nombre, apellido, fecha_nacimiento, edad, foto_perfil, grado, curso, pais, ciudad, role
    const sql = `
      INSERT INTO users
        (username, email, password_hash, nombre, apellido, fecha_nacimiento,
         edad, foto_perfil, grado, curso, pais, ciudad, role)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) 
    `;

    // CORRECCIÓN: Se elimina el uso de la variable 'role' no definida y se usa el literal 'user' directamente.
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
      ciudad || null,
      'user' // 💡 Valor fijo para el rol por defecto.
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
        username: user.username,
        role: user.role
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

// ------------- PERFIL: obtener ------------------------
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

// ------------- PERFIL: actualizar ------------------------
app.put('/api/profile', auth, async (req, res) => {
  const userId = req.user.id;
  const {
    nombre,
    apellido,
    grado,
    curso,
    edad,
    fecha_nacimiento,
    ciudad,
    pais,
    foto_perfil,
  } = req.body;

  // Corregir la validación de campos obligatorios para el UPDATE
  if (!nombre || !apellido) {
      return res.status(400).json({ error: 'Nombre y apellido son obligatorios.' });
  }

  try {
    const sql = `
      UPDATE users
      SET nombre = ?,
          apellido = ?,
          grado = ?,
          curso = ?,
          edad = ?,
          fecha_nacimiento = ?,
          ciudad = ?,
          pais = ?,
          foto_perfil = ?
      WHERE id = ?
    `;

    const [result] = await db.query(sql,
      [
        nombre,
        apellido,
        grado || null,
        curso || null,
        edad || null,
        fecha_nacimiento || null,
        ciudad || null,
        pais || null,
        foto_perfil || null,
        userId
      ]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Usuario no encontrado o sin cambios' });
    }

    res.json({ message: 'Perfil actualizado' });
  } catch (err) {
    console.error('Error actualizando perfil', err);
    res.status(500).json({ error: 'Error al actualizar el perfil' });
  }
});

// ------------- SEGURIDAD: cambiar contraseña ------------------------
app.post('/api/change-password', auth, async (req, res) => {
  const userId = req.user.id;
  const { currentPassword, newPassword } = req.body;

  if (!currentPassword || !newPassword) {
    return res.status(400).json({ error: 'Faltan datos' });
  }

  try {
    const [userRes] = await db.query(
      'SELECT password_hash FROM users WHERE id = ?',
      [userId]
    );

    if (userRes.length === 0) {
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }

    const passwordHash = userRes[0].password_hash;
    const ok = await bcrypt.compare(currentPassword, passwordHash);
    if (!ok) {
      return res.status(401).json({ error: 'Contraseña actual incorrecta' });
    }

    const newHash = await bcrypt.hash(newPassword, 10);
    await db.query(
      'UPDATE users SET password_hash = ? WHERE id = ?',
      [newHash, userId]
    );

    res.json({ message: 'Contraseña actualizada correctamente' });
  } catch (err) {
    console.error('Error cambiando contraseña', err);
    res.status(500).json({ error: 'Error al cambiar la contraseña' });
  }
});

// ------------- CUENTA: eliminar cuenta ------------------------
app.delete('/api/account', auth, async (req, res) => {
  const userId = req.user.id;
  const { password } = req.body;

  if (!password) {
    return res.status(400).json({ error: 'Contraseña requerida' });
  }

  try {
    const [userRes] = await db.query(
      'SELECT password_hash FROM users WHERE id = ?',
      [userId]
    );

    if (userRes.length === 0) {
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }

    const passwordHash = userRes[0].password_hash;
    const ok = await bcrypt.compare(password, passwordHash);
    if (!ok) {
      return res.status(401).json({ error: 'Contraseña incorrecta' });
    }

    // El borrado en cascada se delega a la configuración de la BD,
    // pero aquí eliminamos el registro principal.
    const [deleteResult] = await db.query('DELETE FROM users WHERE id = ?', [userId]);

    if (deleteResult.affectedRows === 0) {
        return res.status(500).json({ error: 'Error al intentar eliminar el usuario' });
    }

    res.json({ message: 'Cuenta eliminada' });
  } catch (err) {
    console.error('Error eliminando cuenta', err);
    res.status(500).json({ error: 'Error al eliminar la cuenta' });
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

// ------------- PUBLICACIONES: formulario para crear nueva (datos del usuario logueado) ---
app.get('/api/publicaciones/nueva', auth, async (req, res) => {
  try {
    const [rows] = await db.query(
      `SELECT id, username, nombre, apellido, foto_perfil, grado, ciudad 
       FROM users WHERE id = ?`, 
      [req.user.id]
    );
    res.json(rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error obteniendo datos usuario' });
  }
});

// ------------- COMENTARIOS: contar para mostrar en feed ---
app.get('/api/publicaciones/:id/comentarios/count', auth, async (req, res) => {
  const publicacionId = req.params.id;
  try {
    const [rows] = await db.query(
      'SELECT COUNT(*) as total FROM comentarios WHERE publicacion_id = ?', 
      [publicacionId]
    );
    res.json({ count: rows[0].total });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error contando comentarios' });
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

// ------------- TIENDA: listar ofertas recibidas por el usuario --------------------------
app.get('/api/tienda/ofertas-recibidas', auth, async (req, res) => {
    const userId = req.user.id;

    try {
        // 1. Obtener ofertas de la Tienda Escolar
        const [ofertasEscolar] = await db.query(
            `SELECT 
                o.id AS oferta_id,
                o.cantidad,
                o.fecha_creacion,
                u.username AS comprador_username,
                u.foto_perfil AS comprador_foto,
                t.id AS producto_id,
                t.descripcion AS producto_descripcion,
                t.precio AS producto_precio,
                'escolar' AS tipo_tienda
             FROM ofertas_tienda_escolar o
             JOIN tienda_escolar t ON o.producto_id = t.id
             JOIN users u ON o.comprador_id = u.id
             WHERE t.user_id = ?
             ORDER BY o.fecha_creacion DESC`,
            [userId]
        );

        // 2. Obtener ofertas de la Tienda Extraescolar
        const [ofertasExtraescolar] = await db.query(
            `SELECT 
                o.id AS oferta_id,
                o.cantidad,
                o.fecha_creacion,
                u.username AS comprador_username,
                u.foto_perfil AS comprador_foto,
                t.id AS producto_id,
                t.descripcion AS producto_descripcion,
                t.precio AS producto_precio,
                'extraescolar' AS tipo_tienda
             FROM ofertas_tienda_extraescolar o
             JOIN tienda_extraescolar t ON o.producto_id = t.id
             JOIN users u ON o.comprador_id = u.id
             WHERE t.user_id = ?
             ORDER BY o.fecha_creacion DESC`,
            [userId]
        );

        // Combinar y devolver los resultados
        const todasLasOfertas = [...ofertasEscolar, ...ofertasExtraescolar];
        
        // Opcional: ordenar por fecha si se desea
        todasLasOfertas.sort((a, b) => new Date(b.fecha_creacion) - new Date(a.fecha_creacion));

        res.json(todasLasOfertas);

    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Error al obtener las ofertas recibidas" });
    }
});

// ------------- PERFIL: obtener datos de OTRO usuario por ID ------------------------
app.get('/api/users/:id', auth, async (req, res) => {
  const targetId = req.params.id;
  
  // Opcional: Asegurar que el ID es un número válido
  if (isNaN(parseInt(targetId))) {
    return res.status(400).json({ error: "ID de usuario inválido" });
  }

  try {
    // Seleccionar solo campos públicos, excluyendo el email y el hash de contraseña
    const [rows] = await db.query(
      `SELECT id, username, nombre, apellido, fecha_nacimiento, edad,
              foto_perfil, grado, curso, pais, ciudad, created_at, intereses
       FROM users
       WHERE id = ?`,
      [targetId]
    );

    if (rows.length === 0) {
      return res.status(404).json({ error: "Usuario no encontrado" });
    }

    res.json(rows[0]);

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error al obtener perfil del usuario" });
  }
});

// -----------------------------------------------------
// 💡 NUEVA RUTA: BÚSQUEDA DE USUARIOS
// -----------------------------------------------------

app.get('/api/users/search', auth, async (req, res) => {
    const { username } = req.query;

    if (!username) {
        return res.status(400).json({ error: "El parámetro 'username' es obligatorio" });
    }

    try {
        // Buscar usuarios por username, excluyendo al propio usuario
        const [rows] = await db.query(
            `SELECT id, username, nombre, apellido, foto_perfil
             FROM users
             WHERE username LIKE ? AND id != ?
             LIMIT 10`,
            [`%${username}%`, req.user.id]
        );

        res.json(rows);

    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Error al buscar usuarios" });
    }
});


// ------------- CHATS: crear chat privado -------------------------------
app.post('/api/chats/privado', auth, async (req, res) => {
  const { destinatario_id } = req.body;

  if (!destinatario_id) {
    return res.status(400).json({ error: "Falta destinatario_id" });
  }

  // Asegurar que no intenta chatear consigo mismo
  if (destinatario_id == req.user.id) {
    return res.status(400).json({ error: "No puedes crear un chat contigo mismo" });
  }

  try {
    // Comprobar que el destinatario existe
    const [userRows] = await db.query(
      "SELECT id FROM users WHERE id = ?",
      [destinatario_id]
    );

    if (userRows.length === 0) {
      return res.status(404).json({ error: "Usuario destinatario no encontrado" });
    }
    
    // Opcional: Comprobar si ya existe un chat privado entre ellos (para evitar duplicados)
    const [existingChat] = await db.query(
        `SELECT c.id FROM chats c
         JOIN chat_miembros cm1 ON c.id = cm1.chat_id
         JOIN chat_miembros cm2 ON c.id = cm2.chat_id
         WHERE c.es_grupo = 0
           AND cm1.user_id = ? AND cm2.user_id = ?`,
        [req.user.id, destinatario_id]
    );

    if (existingChat.length > 0) {
        return res.status(200).json({
            message: "Chat privado ya existe",
            chat_id: existingChat[0].id
        });
    }


    // Crear chat
    const [chatResult] = await db.query(
      "INSERT INTO chats (es_grupo) VALUES (0)"
    );

    const chatId = chatResult.insertId;

    // Insertar miembros (emisor + destinatario)
    await db.query(
      `INSERT INTO chat_miembros (chat_id, user_id)
       VALUES (?, ?), (?, ?)`,
      [chatId, req.user.id, chatId, destinatario_id]
    );

    return res.status(201).json({
      message: "Chat privado creado",
      chat_id: chatId
    });

  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Error creando chat privado" });
  }
});

// ------------- CHATS: crear chat de grupo ------------------------------
app.post('/api/chats/grupo', auth, async (req, res) => {
  const { nombre, miembros_ids } = req.body;
  // miembros_ids: array de IDs de usuarios (sin incluir al propio usuario, lo añadimos nosotros)

  if (!nombre || !Array.isArray(miembros_ids) || miembros_ids.length === 0) {
    return res.status(400).json({ error: "Nombre y miembros_ids son obligatorios" });
  }

  // Evitar duplicados y asegurarnos de que el creador está incluido
  const miembrosUnicos = Array.from(new Set([...miembros_ids, req.user.id]));

  try {
    // Crear chat
    const [chatResult] = await db.query(
      "INSERT INTO chats (nombre, es_grupo) VALUES (?, 1)",
      [nombre]
    );

    const chatId = chatResult.insertId;

    // Insertar miembros
    const values = miembrosUnicos.map(id => [chatId, id]);
    await db.query(
      "INSERT INTO chat_miembros (chat_id, user_id) VALUES ?",
      [values]
    );

    return res.status(201).json({
      message: "Chat de grupo creado",
      chat_id: chatId
    });

  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Error creando chat de grupo" });
  }
});

// -----------------------------------------------------
// 💡 RUTA MODIFICADA: LISTAR CHATS
// -----------------------------------------------------
// Se mantiene el endpoint, pero se añade lógica para buscar el nombre del otro usuario en chats privados.

app.get('/api/chats', auth, async (req, res) => {
  try {
    const userId = req.user.id;
    
    const [rows] = await db.query(
      `SELECT 
         c.id,
         c.nombre,
         c.es_grupo,
         c.created_at
       FROM chats c
       JOIN chat_miembros cm ON c.id = cm.chat_id
       WHERE cm.user_id = ?
       ORDER BY c.created_at DESC`,
      [userId]
    );

    // Para los chats privados (es_grupo = 0), necesitamos la info del otro usuario
    const chatsConInfo = await Promise.all(rows.map(async (chat) => {
        if (!chat.es_grupo) {
            // Es privado, buscar el ID y el nombre del otro usuario
            const [miembros] = await db.query(
                `SELECT u.id, u.username, u.foto_perfil
                 FROM chat_miembros cm
                 JOIN users u ON cm.user_id = u.id
                 WHERE cm.chat_id = ? AND cm.user_id != ?`,
                [chat.id, userId]
            );

            if (miembros.length > 0) {
                // Sobreescribir el nombre del chat con el username del otro
                chat.nombre = miembros[0].username;
                chat.foto_perfil = miembros[0].foto_perfil;
                chat.destinatario_id = miembros[0].id; // Añadir ID para referencia
            }
        }
        return chat;
    }));

    res.json(chatsConInfo);

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error al obtener chats" });
  }
});

// -----------------------------------------------------
// 💡 RUTA MODIFICADA: ENVIAR MENSAJES
// -----------------------------------------------------
// Se añade la emisión del mensaje por socket después de guardarlo.

app.post('/api/chats/:id/mensajes', auth, async (req, res) => {
  const chatId = req.params.id;
  const { contenido } = req.body;
  
  // 💡 OBTENER LA INSTANCIA DE SOCKET.IO
  const io = req.app.get('socketio'); 

  if (!contenido) {
    return res.status(400).json({ error: "El contenido del mensaje es obligatorio" });
  }

  try {
    // Comprobar que el usuario pertenece al chat
    const esMiembro = await userIsMemberOfChat(chatId, req.user.id);
    if (!esMiembro) {
      return res.status(403).json({ error: "No perteneces a este chat" });
    }

    // 1. Insertar en la BD
    const [result] = await db.query(
      `INSERT INTO mensajes (chat_id, user_id, contenido)
       VALUES (?, ?, ?)`,
      [chatId, req.user.id, contenido]
    );

    // 2. Obtener datos completos del mensaje para enviar por socket
    const [mensajeCompleto] = await db.query(
      `SELECT 
         m.id,
         m.contenido,
         m.fecha_envio,
         u.id AS user_id,
         u.username,
         u.foto_perfil
       FROM mensajes m
       JOIN users u ON m.user_id = u.id
       WHERE m.id = ?`,
      [result.insertId]
    );

    // 💡 CAMBIO CRÍTICO: Añadir el chat_id explícitamente al objeto antes de emitir.
    const messageData = {
        ...mensajeCompleto[0], // Contiene id, contenido, fecha_envio, user_id, username, foto_perfil
        chat_id: Number(chatId) // El cliente lo necesita para saber si debe mostrarlo
    };
    
    // 3. Emitir mensaje a la sala de chat
    const roomName = `chat-${chatId}`;
    if (io) {
        // Enviar a todos los sockets conectados a la sala (incluido el emisor, que ya lo verá
        // pintado gracias a la llamada API, pero así se asegura)
        io.to(roomName).emit('chat:message', messageData);
    }

    return res.status(201).json({
      message: "Mensaje enviado",
      id: result.insertId
    });

  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Error enviando mensaje" });
  }
});


// ------------- MENSAJES: listar mensajes de un chat --------------------
// Se mantiene esta ruta, ya que solo se usa para cargar el historial de mensajes al inicio.
app.get('/api/chats/:id/mensajes', auth, async (req, res) => {
  const chatId = req.params.id;
  const limit = parseInt(req.query.limit, 10) || 50;

  try {
    // Comprobar que el usuario pertenece al chat
    const esMiembro = await userIsMemberOfChat(chatId, req.user.id);
    if (!esMiembro) {
      return res.status(403).json({ error: "No perteneces a este chat" });
    }

    const [rows] = await db.query(
      `SELECT 
         m.id,
         m.contenido,
         m.fecha_envio,
         u.id AS user_id,
         u.username,
         u.foto_perfil
       FROM mensajes m
       JOIN users u ON m.user_id = u.id
       WHERE m.chat_id = ?
       ORDER BY m.fecha_envio ASC
       LIMIT ?`,
      [chatId, limit]
    );

    res.json(rows);

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error al obtener mensajes" });
  }
});


// -----------------------------------------------------
// 💡 CONFIGURACIÓN FINAL DEL SERVIDOR (MODIFICADA)
// -----------------------------------------------------

// LÓGICA DE CONEXIÓN DE SOCKET.IO
io.on('connection', (socket) => {
    console.log(`Usuario conectado por socket: ${socket.user.username} (ID: ${socket.user.id})`);
    
    // Evento para UNIRSE A UNA SALA DE CHAT
    socket.on('chat:join', (chatId) => {
        // Abandonar salas anteriores
        Object.keys(socket.rooms).forEach(room => {
            if (room !== socket.id) {
                socket.leave(room);
            }
        });
        const roomName = `chat-${chatId}`;
        socket.join(roomName);
        console.log(`Usuario ${socket.user.username} se unió a la sala ${roomName}`);
    });

    // Evento de desconexión
    socket.on('disconnect', () => {
        console.log(`Usuario desconectado por socket: ${socket.user.username}`);
    });
});

// 💡 HACER LA INSTANCIA DE 'io' ACCESIBLE
// Esto permite acceder a `io` desde las rutas REST usando req.app.get('socketio')
app.set('socketio', io); 

// Lanzar servidor HTTP/Socket.io
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => { 
  console.log("Servidor arrancado en el puerto " + PORT);
});
