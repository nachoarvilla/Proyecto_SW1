const API = "http://localhost:3000";
const token = localStorage.getItem("token");
const user = JSON.parse(localStorage.getItem("user"));

const socket = io(API);

const listInd = document.getElementById("list-ind");
const listGrp = document.getElementById("list-grp");
const thread = document.getElementById("mensajes");
const input = document.getElementById("mensajeInput");
const btn = document.getElementById("enviarBtn");

let currentChat = null;

// ✅ Cargar chats
async function loadChats() {
  const res = await fetch(API + "/api/chats", {
    headers: { Authorization: "Bearer " + token }
  });
  const chats = await res.json();

  if (!Array.isArray(chats)) {
  console.warn("La API devolvió:", chats);
  return; // evita el crash
  }

  listInd.innerHTML = "";
  listGrp.innerHTML = "";

  chats.forEach(c => {
    const btn = document.createElement("button");
    btn.className = "ch-item";
    btn.textContent = c.nombre || "Chat";

    btn.onclick = () => openChat(c.id);

    if (c.es_grupo) listGrp.appendChild(btn);
    else listInd.appendChild(btn);
  });
}

// ✅ Abrir chat
async function openChat(chatId) {
  currentChat = chatId;
  thread.innerHTML = "";

  socket.emit("join_chat", chatId);

  const res = await fetch(`${API}/api/chats/${chatId}/mensajes`, {
    headers: { Authorization: "Bearer " + token }
  });

  const mensajes = await res.json();

  mensajes.forEach(m => addMessage(m, m.user_id === user.id));
  input.disabled = false;
  btn.disabled = false;
}

// ✅ Mostrar mensaje
function addMessage(m, mine) {
  const div = document.createElement("div");
  div.className = mine ? "msg msg-out" : "msg msg-in";
  div.innerHTML = `<p>${m.contenido}</p><time>${new Date(m.fecha_envio).toLocaleTimeString()}</time>`;
  thread.appendChild(div);
}

// ✅ Enviar mensaje
btn.onclick = async () => {
  const texto = input.value.trim();
  if (!texto) return;

  await fetch(`${API}/api/chats/${currentChat}/mensajes`, {
    method: "POST",
    headers: {
      Authorization: "Bearer " + token,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ contenido: texto })
  });

  input.value = "";
};

// ✅ Recibir mensajes realtime
socket.on("new_message", (msg) => {
  if (msg.chatId === currentChat) {
    addMessage(msg, msg.user.id === user.id);
  } else {
    console.log("🔔 Nuevo mensaje en otro chat");
  }
});

// ✅ Buscar usuario
const search = document.getElementById("search-user");
const results = document.getElementById("search-results");

search.oninput = async () => {
  const q = search.value.trim();
  if (!q) return results.innerHTML = "";

  const res = await fetch(`${API}/api/users/search?q=${q}`, {
    headers: { Authorization: "Bearer " + token }
  });

  const users = await res.json();

  results.innerHTML = "";
  users.forEach(u => {
    const btn = document.createElement("button");
    btn.textContent = u.username;
    btn.onclick = () => createPrivateChat(u.id);
    results.appendChild(btn);
  });
};

// ✅ Crear chat privado
async function createPrivateChat(destId) {
  const res = await fetch(`${API}/api/chats/privado`, {
    method: "POST",
    headers: {
      Authorization: "Bearer " + token,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ destinatario_id: destId })
  });

  const data = await res.json();
  loadChats();
}

// ✅ Inicializar todo
loadChats();
