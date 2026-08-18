require("dotenv").config();

const path = require("path");
const fs = require("fs");
const http = require("http");
const express = require("express");
const { Server } = require("socket.io");
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

// ======================================================
// CONFIGURAÇÃO
// ======================================================

const app = express();
const server = http.createServer(app);

const PORT = process.env.PORT || 3000;

const JWT_SECRET =
  process.env.JWT_SECRET ||
  "valtrix-chave-temporaria-troque-em-producao";

// ======================================================
// SOCKET.IO
// ======================================================

const io = new Server(server, {
  cors: {
    origin: true,
    credentials: true
  }
});

// ======================================================
// BANCO DE DADOS
// ======================================================

const DATA_DIR = path.join(__dirname, "data");

if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, {
    recursive: true
  });
}

const DATABASE_FILE = path.join(
  DATA_DIR,
  "valtrix.db"
);

console.log("Diretório do banco:", DATA_DIR);
console.log("Banco:", DATABASE_FILE);

const db = new Database(DATABASE_FILE);

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

console.log("Banco de dados inicializado.");

// ======================================================
// EXPRESS
// ======================================================

app.use(express.json());

app.use(
  express.static(
    path.join(__dirname, "public")
  )
);

// ======================================================
// FUNÇÕES
// ======================================================

function createToken(user) {
  return jwt.sign(
    {
      id: user.id,
      username: user.username,
      displayName: user.display_name
    },
    JWT_SECRET,
    {
      expiresIn: "30d"
    }
  );
}

function authenticate(req, res, next) {
  try {
    const authorization =
      req.headers.authorization || "";

    if (!authorization.startsWith("Bearer ")) {
      return res.status(401).json({
        error: "Não autenticado."
      });
    }

    const token =
      authorization.substring(7);

    req.user = jwt.verify(
      token,
      JWT_SECRET
    );

    next();
  } catch (error) {
    return res.status(401).json({
      error: "Token inválido ou expirado."
    });
  }
}

function getUserById(id) {
  return db
    .prepare(`
      SELECT
        id,
        username,
        display_name
      FROM users
      WHERE id = ?
    `)
    .get(id);
}

function getGroupForUser(
  groupId,
  userId
) {
  return db
    .prepare(`
      SELECT
        g.id,
        g.name,
        g.owner_id,
        g.created_at
      FROM groups g
      INNER JOIN group_members gm
        ON gm.group_id = g.id
      WHERE
        g.id = ?
        AND gm.user_id = ?
    `)
    .get(
      groupId,
      userId
    );
}

function getGroupMembers(groupId) {
  return db
    .prepare(`
      SELECT
        u.id,
        u.username,
        u.display_name
      FROM users u
      INNER JOIN group_members gm
        ON gm.user_id = u.id
      WHERE gm.group_id = ?
      ORDER BY u.display_name
    `)
    .all(groupId);
}

// ======================================================
// CONFIGURAÇÃO WEBRTC
// ======================================================

app.get(
  "/api/config",
  (req, res) => {
    const iceServers = [
      {
        urls:
          "stun:stun.l.google.com:19302"
      }
    ];

    if (process.env.TURN_URL) {
      iceServers.push({
        urls: process.env.TURN_URL,
        username:
          process.env.TURN_USERNAME || "",
        credential:
          process.env.TURN_CREDENTIAL || ""
      });
    }

    res.json({
      iceServers
    });
  }
);

// ======================================================
// HEALTH CHECK
// ======================================================

app.get(
  "/api/health",
  (req, res) => {
    res.json({
      status: "online",
      app: "Valtrix Chat",
      version: "3.0.0",
      time: new Date().toISOString()
    });
  }
);

// ======================================================
// REGISTRO
// ======================================================

app.post(
  "/api/register",
  (req, res) => {
    try {
      const username = String(
        req.body.username || ""
      )
        .trim()
        .toLowerCase();

      const displayName = String(
        req.body.displayName ||
          username
      )
        .trim()
        .slice(0, 40);

      const password = String(
        req.body.password || ""
      );

      if (
        !/^[a-z0-9_.-]{3,32}$/.test(
          username
        )
      ) {
        return res.status(400).json({
          error:
            "Usuário inválido."
        });
      }

      if (password.length < 6) {
        return res.status(400).json({
          error:
            "A senha precisa ter pelo menos 6 caracteres."
        });
      }

      if (!displayName) {
        return res.status(400).json({
          error:
            "Digite um nome."
        });
      }

      const passwordHash =
        bcrypt.hashSync(
          password,
          12
        );

      const result =
        db.prepare(`
          INSERT INTO users (
            username,
            password_hash,
            display_name,
            created_at
          )
          VALUES (?, ?, ?, ?)
        `).run(
          username,
          passwordHash,
          displayName,
          Date.now()
        );

      const user =
        getUserById(
          result.lastInsertRowid
        );

      const token =
        createToken(user);

      res.json({
        token,
        user
      });
    } catch (error) {
      console.error(
        "Erro no registro:",
        error
      );

      if (
        String(
          error.message
        ).includes(
          "UNIQUE constraint failed"
        )
      ) {
        return res.status(409).json({
          error:
            "Esse usuário já existe."
        });
      }

      res.status(500).json({
        error:
          "Erro interno."
      });
    }
  }
);

// ======================================================
// LOGIN
// ======================================================

app.post(
  "/api/login",
  (req, res) => {
    try {
      const username = String(
        req.body.username || ""
      )
        .trim()
        .toLowerCase();

      const password = String(
        req.body.password || ""
      );

      const user =
        db.prepare(`
          SELECT *
          FROM users
          WHERE username = ?
        `).get(username);

      if (!user) {
        return res.status(401).json({
          error:
            "Usuário ou senha incorretos."
        });
      }

      const validPassword =
        bcrypt.compareSync(
          password,
          user.password_hash
        );

      if (!validPassword) {
        return res.status(401).json({
          error:
            "Usuário ou senha incorretos."
        });
      }

      const token =
        createToken(user);

      res.json({
        token,
        user:
          getUserById(user.id)
      });
    } catch (error) {
      console.error(
        "Erro no login:",
        error
      );

      res.status(500).json({
        error:
          "Erro interno."
      });
    }
  }
);

// ======================================================
// USUÁRIO LOGADO
// ======================================================

app.get(
  "/api/me",
  authenticate,
  (req, res) => {
    const user =
      getUserById(
        req.user.id
      );

    if (!user) {
      return res.status(404).json({
        error:
          "Usuário não encontrado."
      });
    }

    res.json({
      user
    });
  }
);

// ======================================================
// LISTAR GRUPOS
// ======================================================

app.get(
  "/api/groups",
  authenticate,
  (req, res) => {
    const groups =
      db.prepare(`
        SELECT
          g.id,
          g.name,
          g.owner_id,
          g.created_at
        FROM groups g
        INNER JOIN group_members gm
          ON gm.group_id = g.id
        WHERE gm.user_id = ?
        ORDER BY g.id DESC
      `).all(req.user.id);

    res.json({
      groups
    });
  }
);

// ======================================================
// CRIAR GRUPO
// ======================================================

app.post(
  "/api/groups",
  authenticate,
  (req, res) => {
    try {
      const name = String(
        req.body.name || ""
      )
        .trim()
        .slice(0, 60);

      if (!name) {
        return res.status(400).json({
          error:
            "Nome do grupo obrigatório."
        });
      }

      const result =
        db.prepare(`
          INSERT INTO groups (
            name,
            owner_id,
            created_at
          )
          VALUES (?, ?, ?)
        `).run(
          name,
          req.user.id,
          Date.now()
        );

      const groupId =
        result.lastInsertRowid;

      db.prepare(`
        INSERT INTO group_members (
          group_id,
          user_id
        )
        VALUES (?, ?)
      `).run(
        groupId,
        req.user.id
      );

      const group =
        db.prepare(`
          SELECT
            id,
            name,
            owner_id,
            created_at
          FROM groups
          WHERE id = ?
        `).get(groupId);

      res.json({
        group
      });
    } catch (error) {
      console.error(
        "Erro criando grupo:",
        error
      );

      res.status(500).json({
        error:
          "Não foi possível criar o grupo."
      });
    }
  }
);

// ======================================================
// ENTRAR NO GRUPO
// ======================================================

app.post(
  "/api/groups/:id/join",
  authenticate,
  (req, res) => {
    const groupId =
      Number(req.params.id);

    const group =
      db.prepare(`
        SELECT
          id,
          name,
          owner_id,
          created_at
        FROM groups
        WHERE id = ?
      `).get(groupId);

    if (!group) {
      return res.status(404).json({
        error:
          "Grupo não encontrado."
      });
    }

    db.prepare(`
      INSERT OR IGNORE INTO group_members (
        group_id,
        user_id
      )
      VALUES (?, ?)
    `).run(
      groupId,
      req.user.id
    );

    res.json({
      group
    });
  }
);

// ======================================================
// MENSAGENS
// ======================================================

app.get(
  "/api/groups/:id/messages",
  authenticate,
  (req, res) => {
    const groupId =
      Number(req.params.id);

    const group =
      getGroupForUser(
        groupId,
        req.user.id
      );

    if (!group) {
      return res.status(403).json({
        error:
          "Você não pertence ao grupo."
      });
    }

    const messages =
      db.prepare(`
        SELECT
          m.id,
          m.group_id,
          m.text,
          m.created_at,
          u.id AS user_id,
          u.username,
          u.display_name
        FROM messages m
        INNER JOIN users u
          ON u.id = m.user_id
        WHERE m.group_id = ?
        ORDER BY m.id DESC
        LIMIT 100
      `).all(groupId);

    messages.reverse();

    res.json({
      messages
    });
  }
);

// ======================================================
// MEMBROS
// ======================================================

app.get(
  "/api/groups/:id/members",
  authenticate,
  (req, res) => {
    const groupId =
      Number(req.params.id);

    const group =
      getGroupForUser(
        groupId,
        req.user.id
      );

    if (!group) {
      return res.status(403).json({
        error:
          "Você não pertence ao grupo."
      });
    }

    res.json({
      members:
        getGroupMembers(
          groupId
        )
    });
  }
);

// ======================================================
// USUÁRIOS CONECTADOS
// ======================================================

const connectedUsers =
  new Map();

// ======================================================
// SOCKET AUTH
// ======================================================

io.use(
  (socket, next) => {
    try {
      const token =
        socket.handshake.auth?.token;

      if (!token) {
        return next(
          new Error(
            "Não autenticado"
          )
        );
      }

      socket.user =
        jwt.verify(
          token,
          JWT_SECRET
        );

      next();
    } catch (error) {
      next(
        new Error(
          "Token inválido"
        )
      );
    }
  }
);

// ======================================================
// SOCKET.IO
// ======================================================

io.on(
  "connection",
  socket => {
    console.log(
      "Usuário conectado:",
      socket.user.username,
      socket.id
    );

    connectedUsers.set(
      socket.id,
      socket.user
    );

    // ================================================
    // ENTRAR NO GRUPO
    // ================================================

    socket.on(
      "join-group",
      data => {
        const groupId =
          Number(
            data?.groupId
          );

        if (!groupId) {
          return;
        }

        const group =
          getGroupForUser(
            groupId,
            socket.user.id
          );

        if (!group) {
          return;
        }

        socket.join(
          `group:${groupId}`
        );

        socket.data.groupId =
          groupId;

        sendPresence(
          groupId
        );
      }
    );

    // ================================================
    // MENSAGEM
    // ================================================

    socket.on(
      "message",
      data => {
        const groupId =
          Number(
            data?.groupId
          );

        const text =
          String(
            data?.text || ""
          )
            .trim()
            .slice(0, 4000);

        if (!groupId || !text) {
          return;
        }

        const group =
          getGroupForUser(
            groupId,
            socket.user.id
          );

        if (!group) {
          return;
        }

        const result =
          db.prepare(`
            INSERT INTO messages (
              group_id,
              user_id,
              text,
              created_at
            )
            VALUES (?, ?, ?, ?)
          `).run(
            groupId,
            socket.user.id,
            text,
            Date.now()
          );

        const message = {
          id:
            result.lastInsertRowid,

          groupId,

          userId:
            socket.user.id,

          username:
            socket.user.username,

          displayName:
            socket.user.displayName,

          text,

          time:
            Date.now()
        };

        io.to(
          `group:${groupId}`
        ).emit(
          "message",
          message
        );
      }
    );

    // ================================================
    // WEBRTC OFFER
    // ================================================

    socket.on(
      "webrtc-offer",
      data => {
        if (
          !data?.to ||
          !data?.offer
        ) {
          return;
        }

        io.to(
          data.to
        ).emit(
          "webrtc-offer",
          {
            from:
              socket.id,
            offer:
              data.offer
          }
        );
      }
    );

    // ================================================
    // WEBRTC ANSWER
    // ================================================

    socket.on(
      "webrtc-answer",
      data => {
        if (
          !data?.to ||
          !data?.answer
        ) {
          return;
        }

        io.to(
          data.to
        ).emit(
          "webrtc-answer",
          {
            from:
              socket.id,
            answer:
              data.answer
          }
        );
      }
    );

    // ================================================
    // WEBRTC ICE
    // ================================================

    socket.on(
      "webrtc-ice",
      data => {
        if (
          !data?.to ||
          !data?.candidate
        ) {
          return;
        }

        io.to(
          data.to
        ).emit(
          "webrtc-ice",
          {
            from:
              socket.id,
            candidate:
              data.candidate
          }
        );
      }
    );

    // ================================================
    // ESTADO DA CHAMADA
    // ================================================

    socket.on(
      "call-state",
      data => {
        const groupId =
          Number(
            data?.groupId
          );

        if (!groupId) {
          return;
        }

        const group =
          getGroupForUser(
            groupId,
            socket.user.id
          );

        if (!group) {
          return;
        }

        socket
          .to(
            `group:${groupId}`
          )
          .emit(
            "call-state",
            {
              id:
                socket.id,

              username:
                socket.user.displayName,

              type:
                data.type,

              active:
                data.active
            }
          );
      }
    );

    // ================================================
    // DESCONECTAR
    // ================================================

    socket.on(
      "disconnect",
      () => {
        console.log(
          "Usuário desconectado:",
          socket.user.username
        );

        const groupId =
          socket.data.groupId;

        connectedUsers.delete(
          socket.id
        );

        if (groupId) {
          sendPresence(
            groupId
          );
        }
      }
    );
  }
);

// ======================================================
// PRESENÇA
// ======================================================

function sendPresence(
  groupId
) {
  const members =
    getGroupMembers(
      groupId
    );

  const onlineMembers =
    members.map(
      member => ({
        ...member,

        online:
          [
            ...connectedUsers.values()
          ].some(
            user =>
              user.id ===
              member.id
          )
      })
    );

  io.to(
    `group:${groupId}`
  ).emit(
    "presence",
    onlineMembers
  );
}

// ======================================================
// FRONTEND
// ======================================================
//
// IMPORTANTE:
// Não usamos app.get("*"), pois versões
// novas do Express/router podem gerar:
// "Missing parameter name at index 1: *"
//
// ======================================================

app.use(
  (req, res, next) => {
    if (
      req.path.startsWith(
        "/api/"
      )
    ) {
      return next();
    }

    if (
      req.method !== "GET"
    ) {
      return next();
    }

    const indexFile =
      path.join(
        __dirname,
        "public",
        "index.html"
      );

    if (
      fs.existsSync(indexFile)
    ) {
      return res.sendFile(
        indexFile
      );
    }

    res.status(404).send(
      "Valtrix Chat: frontend não encontrado."
    );
  }
);

// ======================================================
// ERRO 404 API
// ======================================================

app.use(
  (req, res) => {
    if (
      req.path.startsWith(
        "/api/"
      )
    ) {
      return res.status(404).json({
        error:
          "Endpoint não encontrado."
      });
    }

    res.status(404).send(
      "Página não encontrada."
    );
  }
);

// ======================================================
// ERROS DO NODE
// ======================================================

process.on(
  "uncaughtException",
  error => {
    console.error(
      "ERRO NÃO TRATADO:",
      error
    );
  }
);

process.on(
  "unhandledRejection",
  error => {
    console.error(
      "PROMISE NÃO TRATADA:",
      error
    );
  }
);

// ======================================================
// INICIAR SERVIDOR
// ======================================================

server.listen(
  PORT,
  "0.0.0.0",
  () => {
    console.log("");
    console.log(
      "======================================"
    );
    console.log(
      "       VALTRIX CHAT V3 ONLINE"
    );
    console.log(
      "======================================"
    );
    console.log(
      `Porta: ${PORT}`
    );
    console.log(
      `Banco: ${DATABASE_FILE}`
    );
    console.log(
      "Socket.IO: ativo"
    );
    console.log(
      "WebRTC signaling: ativo"
    );
    console.log(
      "Servidor pronto."
    );
    console.log(
      "======================================"
    );
    console.log("");
  }
);