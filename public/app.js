let token = localStorage.getItem("valtrix_token");
let me = null;
let socket = null;
let current = null;
let groups = [];
let localStream = null;
let activeCall = false;
let remoteAudioEnabled = true;
const peers = new Map();

let rtcConfig = {
  iceServers: [
    { urls: "stun:stun.l.google.com:19302" }
  ]
};

const $ = id => document.getElementById(id);

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, c => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;"
  }[c]));
}

async function api(url, options = {}) {
  options.headers = {
    ...(options.headers || {}),
    ...(token ? { Authorization: "Bearer " + token } : {}),
    "Content-Type": "application/json"
  };

  const response = await fetch(url, options);
  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    throw new Error(data.error || "Erro");
  }

  return data;
}

let registering = false;

$("loginTab").onclick = () => {
  registering = false;
  $("name").hidden = true;
  $("authBtn").textContent = "Entrar";
};

$("regTab").onclick = () => {
  registering = true;
  $("name").hidden = false;
  $("authBtn").textContent = "Criar conta";
};

$("authBtn").onclick = async () => {
  try {
    const body = {
      username: $("user").value,
      password: $("pass").value
    };

    if (registering) {
      body.displayName = $("name").value;
    }

    const data = await api(
      registering ? "/api/register" : "/api/login",
      {
        method: "POST",
        body: JSON.stringify(body)
      }
    );

    token = data.token;
    localStorage.setItem("valtrix_token", token);

    await start();
  } catch (error) {
    $("err").textContent = error.message;
  }
};

async function start() {
  try {
    me = (await api("/api/me")).user;
    rtcConfig = await api("/api/config");

    $("auth").hidden = true;
    $("app").hidden = false;

    $("me").textContent =
      `${me.display_name} @${me.username}`;

    connectSocket();
    await loadGroups();
  } catch {
    localStorage.removeItem("valtrix_token");
    location.reload();
  }
}

function connectSocket() {
  socket = io({
    auth: { token },
    transports: ["websocket", "polling"]
  });

  socket.on("connect", () => {
    $("status").textContent = "online";

    if (current) {
      socket.emit("join-group", {
        groupId: current.id
      });
    }
  });

  socket.on("disconnect", () => {
    $("status").textContent = "offline";
  });

  socket.on("presence", users => {
    $("people").innerHTML = users.map(user => `
      <div class="item">
        ${escapeHtml(user.display_name)}
        <span class="${user.online ? "online" : "offline"}">
          ${user.online ? "● online" : "● offline"}
        </span>
      </div>
    `).join("");
  });

  socket.on("message", message => {
    if (current && current.id === message.groupId) {
      addMessage(message);
    }
  });

  socket.on("call:join", async peerInfo => {
    if (!activeCall) return;

    try {
      await createPeer(peerInfo.peerId, true);
    } catch (error) {
      console.error("Erro criando peer:", error);
    }
  });

  socket.on("call:leave", data => {
    removePeer(data.peerId);
  });

  socket.on("rtc:offer", handleOffer);

  socket.on("rtc:answer", async data => {
    const peer = peers.get(data.from);

    if (!peer) return;

    try {
      await peer.setRemoteDescription(data.answer);
    } catch (error) {
      console.error(error);
    }
  });

  socket.on("rtc:ice", async data => {
    const peer = peers.get(data.from);

    if (!peer || !data.candidate) return;

    try {
      await peer.addIceCandidate(data.candidate);
    } catch (error) {
      console.error(error);
    }
  });

  socket.on("rtc:hangup", data => {
    removePeer(data.from);
  });
}

async function loadGroups() {
  groups = (await api("/api/groups")).groups;

  $("groups").innerHTML = groups.map(group => `
    <div
      class="item ${current?.id === group.id ? "active" : ""}"
      onclick="openGroup(${group.id})"
    >
      ${escapeHtml(group.name)}
    </div>
  `).join("");
}

async function openGroup(id) {
  current = groups.find(group => group.id === id);

  if (!current) return;

  await loadGroups();

  $("title").textContent = current.name;
  $("text").disabled = false;
  $("messages").innerHTML = "";

  if (socket) {
    socket.emit("join-group", {
      groupId: current.id
    });
  }

  try {
    const messages = await api(
      `/api/groups/${current.id}/messages`
    );

    messages.messages.forEach(addMessage);

    const memberData = await api(
      `/api/groups/${current.id}/members`
    );

    renderPeople(memberData.members);
  } catch (error) {
    console.error(error);
  }
}

function renderPeople(users) {
  $("people").innerHTML = users.map(user => `
    <div class="item">
      ${escapeHtml(user.display_name)}
    </div>
  `).join("");
}

function addMessage(message) {
  const mine =
    Number(message.user_id ?? message.userId) === Number(me.id);

  $("messages").insertAdjacentHTML(
    "beforeend",
    `
      <div class="msg ${mine ? "mine" : ""}">
        <div class="meta">
          ${escapeHtml(
            message.display_name ||
            message.displayName ||
            message.username
          )}
        </div>
        <span class="bubble">
          ${escapeHtml(message.text)}
        </span>
      </div>
    `
  );

  $("messages").scrollTop = $("messages").scrollHeight;
}

$("form").onsubmit = event => {
  event.preventDefault();

  const text = $("text").value.trim();

  if (!text || !current || !socket) return;

  socket.emit("message", {
    groupId: current.id,
    text
  });

  $("text").value = "";
};

$("newGroup").onclick = async () => {
  const name = prompt("Nome do grupo:");

  if (!name) return;

  try {
    await api("/api/groups", {
      method: "POST",
      body: JSON.stringify({ name })
    });

    await loadGroups();
  } catch (error) {
    alert(error.message);
  }
};

async function getLocalMedia(type) {
  if (localStream) return localStream;

  if (type === "screen") {
    localStream = await navigator.mediaDevices.getDisplayMedia({
      video: true,
      audio: true
    });
  } else {
    localStream = await navigator.mediaDevices.getUserMedia({
      audio: true,
      video: type === "video"
    });
  }

  const video = document.createElement("video");
  video.id = "local";
  video.autoplay = true;
  video.muted = true;
  video.playsInline = true;
  video.srcObject = localStream;

  $("videos").prepend(video);

  return localStream;
}

async function startCall(type) {
  if (!current) {
    alert("Escolha um grupo primeiro.");
    return;
  }

  try {
    await getLocalMedia(type);

    activeCall = true;
    $("callState").textContent = "Chamada ativa";

    socket.emit("call:join", {
      groupId: current.id,
      kind: type
    });
  } catch (error) {
    alert(
      "Não foi possível acessar câmera/microfone/tela: " +
      error.message
    );
  }
}

async function createPeer(peerId, initiator) {
  if (peers.has(peerId)) {
    return peers.get(peerId);
  }

  const peer = new RTCPeerConnection(rtcConfig);

  peers.set(peerId, peer);

  if (localStream) {
    localStream.getTracks().forEach(track => {
      peer.addTrack(track, localStream);
    });
  }

  peer.onicecandidate = event => {
    if (!event.candidate) return;

    socket.emit("rtc:ice", {
      to: peerId,
      candidate: event.candidate,
      callId: current?.id
    });
  };

  peer.ontrack = event => {
    let video = document.getElementById("remote-" + peerId);

    if (!video) {
      video = document.createElement("video");
      video.id = "remote-" + peerId;
      video.autoplay = true;
      video.playsInline = true;

      $("videos").appendChild(video);
    }

    video.srcObject = event.streams[0];
    video.muted = !remoteAudioEnabled;
  };

  peer.onconnectionstatechange = () => {
    if (
      ["failed", "closed", "disconnected"]
        .includes(peer.connectionState)
    ) {
      removePeer(peerId);
    }
  };

  if (initiator) {
    const offer = await peer.createOffer();
    await peer.setLocalDescription(offer);

    socket.emit("rtc:offer", {
      to: peerId,
      offer,
      callId: current?.id
    });
  }

  return peer;
}

async function handleOffer(data) {
  if (!activeCall) return;

  try {
    await getLocalMedia("voice");

    const peer = await createPeer(
      data.from,
      false
    );

    await peer.setRemoteDescription(data.offer);

    const answer = await peer.createAnswer();
    await peer.setLocalDescription(answer);

    socket.emit("rtc:answer", {
      to: data.from,
      answer,
      callId: current?.id
    });
  } catch (error) {
    console.error(error);
  }
}

function removePeer(peerId) {
  const peer = peers.get(peerId);

  if (peer) {
    peer.close();
    peers.delete(peerId);
  }

  const video = document.getElementById(
    "remote-" + peerId
  );

  if (video) {
    video.remove();
  }
}

$("voice").onclick = () => startCall("voice");
$("video").onclick = () => startCall("video");
$("screen").onclick = () => startCall("screen");

$("mic").onclick = () => {
  if (!localStream) return;

  localStream.getAudioTracks().forEach(track => {
    track.enabled = !track.enabled;
  });
};

$("cam").onclick = () => {
  if (!localStream) return;

  localStream.getVideoTracks().forEach(track => {
    track.enabled = !track.enabled;
  });
};

$("audio").onclick = () => {
  remoteAudioEnabled = !remoteAudioEnabled;

  document.querySelectorAll(
    "#videos video:not(#local)"
  ).forEach(video => {
    video.muted = !remoteAudioEnabled;
  });
};

$("hang").onclick = () => {
  if (current && socket) {
    socket.emit("call:leave", {
      groupId: current.id
    });
  }

  for (const peerId of peers.keys()) {
    removePeer(peerId);
  }

  if (localStream) {
    localStream.getTracks().forEach(track => track.stop());
  }

  localStream = null;
  activeCall = false;

  $("videos").innerHTML = "";
  $("callState").textContent = "Sem chamada";
};

if (token) {
  start();
}