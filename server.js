require("dotenv").config();

const path = require("path");
const fs = require("fs");
const http = require("http");
const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const Database = require("better-sqlite3");
const { Server } = require("socket.io");

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: true, credentials: true }
});

const PORT = Number(process.env.PORT || 3000);
const JWT_SECRET = process.env.JWT_SECRET || "change-this-valtrix-secret";

const dataDir = path.join(__dirname, "data");
fs.mkdirSync(dataDir, { recursive: true });

const db = new Database(path.join(dataDir, "valtrix.db"));
db.pragma("journal_mode = WAL");

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  display_name TEXT NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS groups (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  owner_id INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS group_members (
  group_id INTEGER NOT NULL,
  user_id INTEGER NOT NULL,
  PRIMARY KEY (group_id, user_id)
);

CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  group_id INTEGER NOT NULL,
  user_id INTEGER NOT NULL,
  text TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
`);

app.use(express.json({ limit: "1mb" }));
app.use(express.static(path.join(__dirname, "public")));

function userById(id) {
  return db.prepare(
    "SELECT id, username, display_name FROM users WHERE id = ?"
  ).get(id);
}

function makeToken(user) {
  return jwt.sign(
    {
      id: user.id,
      username: user.username,
      displayName: user.display_name
    },
    JWT_SECRET,
    { expiresIn: "30d" }
  );
}

function auth(req, res, next) {
  try {
    const header = req.headers.authorization || "";
    if (!header.startsWith("Bearer ")) {
      return res.status(401).json({ error: "Não autenticado" });
    }

    req.user = jwt.verify(header.slice(7), JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: "Sessão inválida ou expirada" });
  }
}

function isMember(groupId, userId) {
  return !!db.prepare(
    "SELECT 1 FROM group_members WHERE group_id = ? AND user_id = ?"
  ).get(groupId, userId);
}

function getMembers(groupId) {
  return db.prepare(`
    SELECT u.id, u.username, u.display_name
    FROM users u
    JOIN group_members gm ON gm.user_id = u.id
    WHERE gm.group_id = ?
    ORDER BY u.display_name
  `).all(groupId);
}

app.get("/api/health", (req, res) => {
  res.json({ ok: true, app: "Valtrix", version: "4.0.0" });
});

app.get("/api/config", (req, res) => {
  const iceServers = [
    { urls: "stun:stun.l.google.com:19302" }
  ];

  if (process.env.TURN_URL) {
    iceServers.push({
      urls: process.env.TURN_URL,
      username: process.env.TURN_USERNAME || "",
      credential: process.env.TURN_CREDENTIAL || ""
    });
  }

  res.json({ iceServers });
});

app.post("/api/register", (req, res) => {
  try {
    const username = String(req.body.username || "").trim().toLowerCase();
    const displayName = String(
      req.body.displayName || username
    ).trim().slice(0, 40);
    const password = String(req.body.password || "");

    if (!/^[a-z0-9_.-]{3,32}$/.test(username)) {
      return res.status(400).json({
        error: "Usuário inválido. Use 3-32 caracteres: letras, números, _, . ou -."
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        error: "A senha precisa ter pelo menos 6 caracteres."
      });
    }

    const hash = bcrypt.hashSync(password, 12);

    const result = db.prepare(`
      INSERT INTO users(username, password_hash, display_name, created_at)
      VALUES (?, ?, ?, ?)
    `).run(username, hash, displayName, Date.now());

    const user = userById(result.lastInsertRowid);

    res.json({
      token: makeToken(user),
      user
    });
  } catch (error) {
    if (String(error.message).includes("UNIQUE")) {
      return res.status(409).json({ error: "Esse usuário já existe." });
    }

    console.error(error);
    res.status(500).json({ error: "Erro ao criar conta." });
  }
});

app.post("/api/login", (req, res) => {
  const username = String(req.body.username || "").trim().toLowerCase();
  const password = String(req.body.password || "");

  const user = db.prepare(
    "SELECT * FROM users WHERE username = ?"
  ).get(username);

  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    return res.status(401).json({
      error: "Usuário ou senha incorretos."
    });
  }

  res.json({
    token: makeToken(user),
    user: userById(user.id)
  });
});

app.get("/api/me", auth, (req, res) => {
  const user = userById(req.user.id);

  if (!user) {
    return res.status(404).json({ error: "Usuário não encontrado." });
  }

  res.json({ user });
});

app.get("/api/users", auth, (req, res) => {
  const q = String(req.query.q || "").trim().toLowerCase();

  const users = db.prepare(`
    SELECT id, username, display_name
    FROM users
    WHERE id <> ?
      AND (username LIKE ? OR display_name LIKE ?)
    ORDER BY display_name
    LIMIT 50
  `).all(req.user.id, `%${q}%`, `%${q}%`);

  res.json({ users });
});

app.get("/api/groups", auth, (req, res) => {
  const groups = db.prepare(`
    SELECT g.id, g.name, g.owner_id, g.created_at
    FROM groups g
    JOIN group_members gm ON gm.group_id = g.id
    WHERE gm.user_id = ?
    ORDER BY g.id DESC
  `).all(req.user.id);

  res.json({ groups });
});

app.post("/api/groups", auth, (req, res) => {
  const name = String(req.body.name || "").trim().slice(0, 60);

  if (!name) {
    return res.status(400).json({ error: "Nome do grupo obrigatório." });
  }

  const result = db.prepare(`
    INSERT INTO groups(name, owner_id, created_at)
    VALUES (?, ?, ?)
  `).run(name, req.user.id, Date.now());

  db.prepare(`
    INSERT INTO group_members(group_id, user_id)
    VALUES (?, ?)
  `).run(result.lastInsertRowid, req.user.id);

  const group = db.prepare(
    "SELECT id, name, owner_id, created_at FROM groups WHERE id = ?"
  ).get(result.lastInsertRowid);

  res.json({ group });
});

app.post("/api/groups/:id/join", auth, (req, res) => {
  const groupId = Number(req.params.id);

  const group = db.prepare(
    "SELECT id, name, owner_id, created_at FROM groups WHERE id = ?"
  ).get(groupId);

  if (!group) {
    return res.status(404).json({ error: "Grupo não encontrado." });
  }

  db.prepare(`
    INSERT OR IGNORE INTO group_members(group_id, user_id)
    VALUES (?, ?)
  `).run(groupId, req.user.id);

  res.json({ group });
});

app.get("/api/groups/:id/messages", auth, (req, res) => {
  const groupId = Number(req.params.id);

  if (!isMember(groupId, req.user.id)) {
    return res.status(403).json({
      error: "Você não pertence a este grupo."
    });
  }

  const messages = db.prepare(`
    SELECT
      m.id,
      m.group_id,
      m.text,
      m.created_at,
      u.id AS user_id,
      u.username,
      u.display_name
    FROM messages m
    JOIN users u ON u.id = m.user_id
    WHERE m.group_id = ?
    ORDER BY m.id DESC
    LIMIT 100
  `).all(groupId).reverse();

  res.json({ messages });
});

app.get("/api/groups/:id/members", auth, (req, res) => {
  const groupId = Number(req.params.id);

  if (!isMember(groupId, req.user.id)) {
    return res.status(403).json({
      error: "Você não pertence a este grupo."
    });
  }

  res.json({ members: getMembers(groupId) });
});

const socketsByUser = new Map();

function sendPresence(groupId) {
  const users = getMembers(groupId).map(user => ({
    ...user,
    online: (socketsByUser.get(user.id)?.size || 0) > 0
  }));

  io.to(`group:${groupId}`).emit("presence", users);
}

io.use((socket, next) => {
  try {
    const token = socket.handshake.auth?.token;

    if (!token) {
      return next(new Error("AUTH_REQUIRED"));
    }

    socket.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    next(new Error("AUTH_INVALID"));
  }
});

io.on("connection", socket => {
  const userId = socket.user.id;

  if (!socketsByUser.has(userId)) {
    socketsByUser.set(userId, new Set());
  }

  socketsByUser.get(userId).add(socket.id);
  socket.join(`user:${userId}`);
  socket.data.groups = new Set();

  socket.on("join-group", data => {
    const groupId = Number(data?.groupId);

    if (!isMember(groupId, userId)) return;

    socket.join(`group:${groupId}`);
    socket.data.groups.add(groupId);

    sendPresence(groupId);
  });

  socket.on("message", data => {
    const groupId = Number(data?.groupId);
    const text = String(data?.text || "").trim().slice(0, 4000);

    if (!text || !isMember(groupId, userId)) return;

    const result = db.prepare(`
      INSERT INTO messages(group_id, user_id, text, created_at)
      VALUES (?, ?, ?, ?)
    `).run(groupId, userId, text, Date.now());

    const user = userById(userId);

    io.to(`group:${groupId}`).emit("message", {
      id: result.lastInsertRowid,
      groupId,
      userId,
      username: user.username,
      displayName: user.display_name,
      text,
      time: Date.now()
    });
  });

  // WebRTC signaling: oferta
  socket.on("rtc:offer", data => {
    if (data?.to && data.offer) {
      io.to(data.to).emit("rtc:offer", {
        from: socket.id,
        offer: data.offer,
        callId: data.callId,
        user: socket.user
      });
    }
  });

  // WebRTC signaling: resposta
  socket.on("rtc:answer", data => {
    if (data?.to && data.answer) {
      io.to(data.to).emit("rtc:answer", {
        from: socket.id,
        answer: data.answer,
        callId: data.callId
      });
    }
  });

  // WebRTC signaling: ICE
  socket.on("rtc:ice", data => {
    if (data?.to && data.candidate) {
      io.to(data.to).emit("rtc:ice", {
        from: socket.id,
        candidate: data.candidate,
        callId: data.callId
      });
    }
  });

  socket.on("rtc:hangup", data => {
    if (data?.to) {
      io.to(data.to).emit("rtc:hangup", {
        from: socket.id,
        callId: data.callId
      });
    }
  });

  // Controle da sala de chamada
  socket.on("call:join", data => {
    const groupId = Number(data?.groupId);

    if (!isMember(groupId, userId)) return;

    socket.to(`group:${groupId}`).emit("call:join", {
      peerId: socket.id,
      user: socket.user,
      kind: data.kind
    });
  });

  socket.on("call:leave", data => {
    const groupId = Number(data?.groupId);

    if (!isMember(groupId, userId)) return;

    socket.to(`group:${groupId}`).emit("call:leave", {
      peerId: socket.id
    });
  });

  socket.on("disconnect", () => {
    const set = socketsByUser.get(userId);

    if (set) {
      set.delete(socket.id);

      if (!set.size) {
        socketsByUser.delete(userId);
      }
    }

    for (const groupId of socket.data.groups) {
      sendPresence(groupId);
    }
  });
});

// IMPORTANTE:
// Express 5 não aceita app.get("*") do mesmo modo que versões antigas.
// Por isso usamos middleware simples para entregar index.html.
app.use((req, res, next) => {
  if (
    req.path.startsWith("/api/") ||
    req.path.startsWith("/socket.io/")
  ) {
    return next();
  }

  if (req.method !== "GET") {
    return next();
  }

  const indexFile = path.join(__dirname, "public", "index.html");

  if (fs.existsSync(indexFile)) {
    return res.sendFile(indexFile);
  }

  res.status(404).send("Valtrix");
});

app.use((req, res) => {
  res.status(404).json({ error: "Não encontrado" });
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(`Valtrix V4 online na porta ${PORT}`);
});