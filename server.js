require("dotenv").config();
const path=require("path");
const http=require("http");
const express=require("express");
const {Server}=require("socket.io");
const Database=require("better-sqlite3");
const bcrypt=require("bcryptjs");
const jwt=require("jsonwebtoken");
const crypto=require("crypto");

const app=express();
const server=http.createServer(app);
const io=new Server(server,{cors:{origin:true,credentials:true}});
const db=new Database(path.join(__dirname,"data","valtrix.db"));
const JWT_SECRET=process.env.JWT_SECRET||"change-me-in-production";

db.pragma("journal_mode = WAL");
db.exec(`
CREATE TABLE IF NOT EXISTS users(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 username TEXT NOT NULL UNIQUE,
 password_hash TEXT NOT NULL,
 display_name TEXT NOT NULL,
 created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS groups(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 name TEXT NOT NULL,
 owner_id INTEGER NOT NULL,
 created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS group_members(
 group_id INTEGER NOT NULL,
 user_id INTEGER NOT NULL,
 PRIMARY KEY(group_id,user_id)
);
CREATE TABLE IF NOT EXISTS messages(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 group_id INTEGER NOT NULL,
 user_id INTEGER NOT NULL,
 text TEXT NOT NULL,
 created_at INTEGER NOT NULL
);
`);

app.use(express.json());
app.use(express.static(path.join(__dirname,"public")));

function tokenFor(user){return jwt.sign({id:user.id,username:user.username,displayName:user.display_name},JWT_SECRET,{expiresIn:"30d"})}
function auth(req,res,next){
 try{const h=req.headers.authorization||"";const t=h.startsWith("Bearer ")?h.slice(7):"";req.user=jwt.verify(t,JWT_SECRET);next()}
 catch(e){res.status(401).json({error:"Não autenticado"})}
}
function userById(id){return db.prepare("SELECT id,username,display_name FROM users WHERE id=?").get(id)}
function groupForUser(groupId,userId){
 return db.prepare(`SELECT g.* FROM groups g JOIN group_members gm ON gm.group_id=g.id WHERE g.id=? AND gm.user_id=?`).get(groupId,userId)
}
function groupMembers(groupId){
 return db.prepare(`SELECT u.id,u.username,u.display_name FROM users u JOIN group_members gm ON gm.user_id=u.id WHERE gm.group_id=? ORDER BY u.display_name`).all(groupId)
}

app.get("/api/config",(req,res)=>{
 const ice=[{urls:"stun:stun.l.google.com:19302"}];
 if(process.env.TURN_URL) ice.push({urls:process.env.TURN_URL,username:process.env.TURN_USERNAME,credential:process.env.TURN_CREDENTIAL});
 res.json({iceServers:ice});
});

app.post("/api/register",(req,res)=>{
 const username=String(req.body.username||"").trim().toLowerCase();
 const displayName=String(req.body.displayName||username).trim().slice(0,40);
 const password=String(req.body.password||"");
 if(!/^[a-z0-9_.-]{3,32}$/.test(username)||password.length<6)return res.status(400).json({error:"Usuário inválido ou senha menor que 6 caracteres."});
 try{
  const hash=bcrypt.hashSync(password,12);
  const r=db.prepare("INSERT INTO users(username,password_hash,display_name,created_at) VALUES(?,?,?,?)").run(username,hash,displayName,Date.now());
  const u=userById(r.lastInsertRowid);
  res.json({token:tokenFor({...u,display_name:u.display_name}),user:u});
 }catch(e){res.status(409).json({error:"Esse usuário já existe."})}
});
app.post("/api/login",(req,res)=>{
 const username=String(req.body.username||"").trim().toLowerCase(),password=String(req.body.password||"");
 const u=db.prepare("SELECT * FROM users WHERE username=?").get(username);
 if(!u||!bcrypt.compareSync(password,u.password_hash))return res.status(401).json({error:"Usuário ou senha incorretos."});
 res.json({token:tokenFor(u),user:userById(u.id)});
});
app.get("/api/me",auth,(req,res)=>res.json({user:userById(req.user.id)}));

app.get("/api/groups",auth,(req,res)=>{
 const groups=db.prepare(`SELECT g.id,g.name,g.owner_id FROM groups g JOIN group_members gm ON gm.group_id=g.id WHERE gm.user_id=? ORDER BY g.id DESC`).all(req.user.id);
 res.json({groups});
});
app.post("/api/groups",auth,(req,res)=>{
 const name=String(req.body.name||"").trim().slice(0,60);
 if(!name)return res.status(400).json({error:"Nome do grupo obrigatório."});
 const r=db.prepare("INSERT INTO groups(name,owner_id,created_at) VALUES(?,?,?)").run(name,req.user.id,Date.now());
 db.prepare("INSERT INTO group_members(group_id,user_id) VALUES(?,?)").run(r.lastInsertRowid,req.user.id);
 res.json({group:{id:r.lastInsertRowid,name,owner_id:req.user.id}});
});
app.post("/api/groups/:id/join",auth,(req,res)=>{
 const g=db.prepare("SELECT id,name FROM groups WHERE id=?").get(req.params.id);
 if(!g)return res.status(404).json({error:"Grupo não encontrado."});
 db.prepare("INSERT OR IGNORE INTO group_members(group_id,user_id) VALUES(?,?)").run(g.id,req.user.id);
 res.json({group:g});
});
app.get("/api/groups/:id/messages",auth,(req,res)=>{
 if(!groupForUser(req.params.id,req.user.id))return res.status(403).json({error:"Sem acesso ao grupo."});
 const rows=db.prepare(`SELECT m.id,m.text,m.created_at,u.id user_id,u.display_name,u.username FROM messages m JOIN users u ON u.id=m.user_id WHERE m.group_id=? ORDER BY m.id DESC LIMIT 100`).all(req.params.id).reverse();
 res.json({messages:rows});
});
app.get("/api/groups/:id/members",auth,(req,res)=>{
 if(!groupForUser(req.params.id,req.user.id))return res.status(403).json({error:"Sem acesso ao grupo."});
 res.json({members:groupMembers(req.params.id)});
});

const sockets=new Map();
io.use((socket,next)=>{
 try{
  const token=socket.handshake.auth?.token;
  socket.user=jwt.verify(token,JWT_SECRET);next();
 }catch(e){next(new Error("Não autenticado"))}
});
io.on("connection",socket=>{
 sockets.set(socket.id,socket.user);
 socket.on("join-group",({groupId})=>{
  if(!groupForUser(groupId,socket.user.id))return;
  socket.join("group:"+groupId);
  socket.data.groupId=Number(groupId);
  io.to("group:"+groupId).emit("presence",groupMembers(groupId).map(u=>({...u,online:[...sockets.values()].some(x=>x.id===u.id)})));
 });
 socket.on("message",({groupId,text})=>{
  const gid=Number(groupId),clean=String(text||"").trim().slice(0,4000);
  if(!clean||!groupForUser(gid,socket.user.id))return;
  const r=db.prepare("INSERT INTO messages(group_id,user_id,text,created_at) VALUES(?,?,?,?)").run(gid,socket.user.id,clean,Date.now());
  const m={id:r.lastInsertRowid,groupId:gid,userId:socket.user.id,username:socket.user.username,displayName:socket.user.displayName,text:clean,time:Date.now()};
  io.to("group:"+gid).emit("message",m);
 });
 socket.on("webrtc-offer",({to,offer})=>io.to(to).emit("webrtc-offer",{from:socket.id,offer}));
 socket.on("webrtc-answer",({to,answer})=>io.to(to).emit("webrtc-answer",{from:socket.id,answer}));
 socket.on("webrtc-ice",({to,candidate})=>io.to(to).emit("webrtc-ice",{from:socket.id,candidate}));
 socket.on("call-state",({groupId,type,active})=>{
  if(!groupForUser(groupId,socket.user.id))return;
  socket.to("group:"+groupId).emit("call-state",{id:socket.id,username:socket.user.displayName,type,active});
 });
 socket.on("disconnect",()=>sockets.delete(socket.id));
});

const PORT=process.env.PORT||3000;
server.listen(PORT,"0.0.0.0",()=>console.log("Valtrix V3 rodando na porta "+PORT));