// Riya Laptop Assistant — Relay Server (v1.0.0)
// ---------------------------------------------------------------
// NEW file, built from scratch for this task. Zero external
// dependencies — only Node.js built-ins (http, crypto). No secrets,
// no pairing codes hardcoded anywhere. A pairing code is only ever
// supplied at runtime by the laptop app and by Riya's control
// client, and must match for the two sides to be paired.
//
// How it works:
//   laptop app  --WS-->  relay  <--WS--  Riya / control client
//   * Both sides first send {"type":"auth","role":"laptop"|"control",
//     "pairingCode":"RIYA-XXXXXX"}.
//   * The relay keeps one "room" per pairing code: at most one
//     laptop + one control client per room.
//   * Control -> laptop: {"type":"command","id":"...","cmd":{...}}
//     The relay validates the command against the same blocklist as
//     the laptop app (commands.js) and rejects password / banking /
//     OTP commands. It never forwards a blocked command.
//   * Laptop -> control: {"type":"result"|"status"|"screenshot", ...}
//     Screenshots are forwarded, but the relay only logs their byte
//     size — never their content.
//   * No code = no connection. Wrong / malformed code = rejected.
//
// Run:  RELAY_PORT=18778 node server.js
// Health: curl http://127.0.0.1:18778/health
// ---------------------------------------------------------------
"use strict";

const http = require("http");
const crypto = require("crypto");

const PORT = parseInt(process.env.RELAY_PORT || process.env.PORT || "18778", 10);
const HOST = process.env.RELAY_HOST || "0.0.0.0";
const MAX_MESSAGE_BYTES = parseInt(process.env.RELAY_MAX_MESSAGE_BYTES || String(2 * 1024 * 1024), 10);
const MAX_CONNECTIONS_PER_MIN_PER_IP = 10;
const MAX_MESSAGES_PER_SEC_PER_SOCKET = 20;
const WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

// --- Same safety rules as the laptop app (commands.js) -------------
const BLOCKED_KEYWORDS = [
  "password", "passwd", "bank", "banking", "otp", "pin code",
  "credit card", "easypaisa", "jazzcash", "login password",
  "one-time password", "2fa code", "recovery code",
];
const BLOCKED_COMMAND_TYPES = ["fill_password", "read_password", "bank_login", "otp_read"];
const ALLOWED_COMMAND_TYPES = [
  "ping", "screenshot", "open_app", "open_path", "list_apps",
  "type_text", "click", "disconnect", "status",
];
const PAIRING_CODE_RE = /^RIYA-[ABCDEFGHJKMNPQRSTUVWXYZ23456789]{6}$/;

function isBlockedText(text) {
  if (!text || typeof text !== "string") return false;
  const t = text.toLowerCase();
  return BLOCKED_KEYWORDS.some((k) => t.includes(k));
}

function validateCommand(cmd) {
  if (!cmd || typeof cmd !== "object") return { ok: false, error: "Command must be a JSON object" };
  if (!cmd.type || typeof cmd.type !== "string") return { ok: false, error: "Missing command type" };
  if (BLOCKED_COMMAND_TYPES.includes(cmd.type)) {
    return { ok: false, error: "Blocked action: " + cmd.type + " is never allowed (password / banking / OTP)" };
  }
  if (isBlockedText(JSON.stringify(cmd))) {
    return { ok: false, error: "Blocked: command mentions a password / banking / OTP action" };
  }
  if (!ALLOWED_COMMAND_TYPES.includes(cmd.type)) return { ok: false, error: "Unknown command type: " + cmd.type };
  if (cmd.type === "open_app" && !cmd.app) return { ok: false, error: "open_app needs an app name, e.g. notepad" };
  if (cmd.type === "open_path" && !cmd.path) return { ok: false, error: "open_path needs a path" };
  if (cmd.type === "type_text" && typeof cmd.text !== "string") return { ok: false, error: "type_text needs text" };
  if (cmd.type === "click" && (typeof cmd.x !== "number" || typeof cmd.y !== "number")) {
    return { ok: false, error: "click needs numeric x and y" };
  }
  return { ok: true };
}

// --- Logging (never log pairing codes or screen content) ----------
function codeHash(code) {
  return crypto.createHash("sha256").update(String(code)).digest("hex").slice(0, 8);
}
function log(...args) {
  console.log(new Date().toISOString(), "[relay]", ...args);
}

// --- WebSocket framing (RFC 6455, built-ins only) -----------------
function encodeFrame(data, opcode = 0x01) {
  const payload = Buffer.isBuffer(data) ? data : Buffer.from(String(data), "utf8");
  const len = payload.length;
  let header;
  if (len < 126) {
    header = Buffer.from([0x80 | opcode, len]);
  } else if (len < 65536) {
    header = Buffer.alloc(4);
    header[0] = 0x80 | opcode;
    header[1] = 126;
    header.writeUInt16BE(len, 2);
  } else {
    header = Buffer.alloc(10);
    header[0] = 0x80 | opcode;
    header[1] = 127;
    header.writeBigUInt64BE(BigInt(len), 2);
  }
  return Buffer.concat([header, payload]);
}
function encodeClose(code = 1000, reason = "") {
  const payload = Buffer.alloc(2 + Buffer.byteLength(reason));
  payload.writeUInt16BE(code, 0);
  payload.write(reason, 2);
  return encodeFrame(payload, 0x08);
}

// Returns { messages: [{opcode, payload: Buffer}], rest: Buffer }
// Handles fragmented messages by accumulating them on the socket.
function parseFrames(socket, chunk) {
  socket._wsBuf = Buffer.concat([socket._wsBuf || Buffer.alloc(0), chunk]);
  const messages = [];
  let buf = socket._wsBuf;
  let offset = 0;
  while (true) {
    if (buf.length - offset < 2) break;
    const b0 = buf[offset];
    const b1 = buf[offset + 1];
    const fin = (b0 & 0x80) !== 0;
    const opcode = b0 & 0x0f;
    const masked = (b1 & 0x80) !== 0;
    let len = b1 & 0x7f;
    let pos = offset + 2;
    if (len === 126) {
      if (buf.length - pos < 2) break;
      len = buf.readUInt16BE(pos);
      pos += 2;
    } else if (len === 127) {
      if (buf.length - pos < 8) break;
      const big = buf.readBigUInt64BE(pos);
      if (big > BigInt(MAX_MESSAGE_BYTES)) throw new Error("Frame too large");
      len = Number(big);
      pos += 8;
    }
    let mask = null;
    if (masked) {
      if (buf.length - pos < 4) break;
      mask = buf.slice(pos, pos + 4);
      pos += 4;
    }
    if (buf.length - pos < len) break;
    let payload = Buffer.from(buf.slice(pos, pos + len));
    if (masked) {
      for (let i = 0; i < payload.length; i++) payload[i] ^= mask[i % 4];
    }
    if (opcode === 0x00) {
      // continuation
      socket._frag = Buffer.concat([socket._frag || Buffer.alloc(0), payload]);
      if (fin) {
        messages.push({ opcode: socket._fragOpcode || 0x01, payload: socket._frag });
        socket._frag = null;
        socket._fragOpcode = null;
      }
    } else if (!fin) {
      socket._frag = payload;
      socket._fragOpcode = opcode;
    } else {
      messages.push({ opcode, payload });
    }
    offset = pos + len;
  }
  socket._wsBuf = buf.slice(offset);
  return messages;
}

// --- Rooms ---------------------------------------------------------
// code -> { codeHash, laptop: Conn|null, control: Conn|null, createdAt }
const rooms = new Map();
// ip -> [ timestamps of recent connection attempts ]
const ipAttempts = new Map();

function getOrCreateRoom(code) {
  let room = rooms.get(code);
  if (!room) {
    room = { codeHash: codeHash(code), laptop: null, control: null, createdAt: new Date().toISOString() };
    rooms.set(code, room);
  }
  return room;
}
function cleanupRoom(code) {
  const room = rooms.get(code);
  if (room && !room.laptop && !room.control) rooms.delete(code);
}

// --- Per-connection state ------------------------------------------
function sendJson(conn, obj) {
  if (!conn || !conn.socket || conn.socket.destroyed) return false;
  try {
    conn.socket.write(encodeFrame(JSON.stringify(obj)));
    return true;
  } catch (e) {
    return false;
  }
}
function closeConn(conn, code, reason) {
  try {
    conn.socket.write(encodeClose(code, reason || ""));
  } catch (e) {}
  try {
    conn.socket.end();
  } catch (e) {}
}
function peerOf(room, role) {
  return role === "laptop" ? room.control : room.laptop;
}

function handleMessage(conn, msg) {
  // Rate limit: max messages/sec per socket.
  const now = Date.now();
  conn.msgTimes = (conn.msgTimes || []).filter((t) => now - t < 1000);
  conn.msgTimes.push(now);
  if (conn.msgTimes.length > MAX_MESSAGES_PER_SEC_PER_SOCKET) {
    sendJson(conn, { ok: false, error: "Rate limit: too many messages" });
    closeConn(conn, 1008, "rate limit");
    return;
  }

  let data;
  try {
    data = JSON.parse(msg);
  } catch (e) {
    sendJson(conn, { ok: false, error: "Not valid JSON" });
    return;
  }
  if (!data || typeof data !== "object") {
    sendJson(conn, { ok: false, error: "Message must be a JSON object" });
    return;
  }

  // --- Auth is mandatory first -------------------------------------
  if (!conn.authenticated) {
    if (data.type !== "auth") {
      sendJson(conn, { ok: false, error: "Authenticate first: send {\"type\":\"auth\",\"role\":\"laptop|control\",\"pairingCode\":\"RIYA-XXXXXX\"}" });
      closeConn(conn, 1008, "auth required");
      return;
    }
    const role = data.role;
    const code = String(data.pairingCode || "").trim().toUpperCase();
    if (role !== "laptop" && role !== "control") {
      sendJson(conn, { ok: false, error: "Invalid role: must be 'laptop' or 'control'" });
      closeConn(conn, 1008, "bad role");
      return;
    }
    if (!PAIRING_CODE_RE.test(code)) {
      log("auth rejected: malformed pairing code from", conn.ip);
      sendJson(conn, { ok: false, error: "Invalid pairing code format" });
      closeConn(conn, 1008, "bad code");
      return;
    }
    const room = getOrCreateRoom(code);
    if (room[role]) {
      log("auth rejected: role already connected", "room=" + room.codeHash, "role=" + role);
      sendJson(conn, { ok: false, error: "A " + role + " client is already connected for this pairing code" });
      closeConn(conn, 1008, "role taken");
      return;
    }
    conn.authenticated = true;
    conn.role = role;
    conn.code = code;
    conn.room = room;
    room[role] = conn;
    const peer = peerOf(room, role);
    log("auth ok", "room=" + room.codeHash, "role=" + role, "peerConnected=" + !!peer);
    sendJson(conn, { ok: true, type: "auth_ok", role, peerConnected: !!peer });
    if (peer) sendJson(peer, { type: "peer_connected", role });
    return;
  }

  // --- Authenticated messages --------------------------------------
  const room = conn.room;
  const peer = peerOf(room, conn.role);

  if (data.type === "ping") {
    sendJson(conn, { type: "pong", id: data.id || null });
    return;
  }

  if (data.type === "command") {
    if (conn.role !== "control") {
      sendJson(conn, { ok: false, error: "Only the control client may send commands" });
      return;
    }
    const v = validateCommand(data.cmd);
    if (!v.ok) {
      log("command blocked", "room=" + room.codeHash, "reason=" + v.error);
      sendJson(conn, { ok: false, id: data.id || null, error: v.error });
      return;
    }
    if (!peer) {
      sendJson(conn, { ok: false, id: data.id || null, error: "Laptop not connected — turn the laptop app on and connect it with the same pairing code" });
      return;
    }
    log("command forwarded", "room=" + room.codeHash, "type=" + data.cmd.type, "id=" + (data.id || "-"));
    sendJson(peer, { type: "command", id: data.id || null, cmd: data.cmd });
    return;
  }

  if (data.type === "result" || data.type === "status" || data.type === "screenshot") {
    if (conn.role !== "laptop") {
      sendJson(conn, { ok: false, error: "Only the laptop may send results / status / screenshots" });
      return;
    }
    if (!peer) {
      sendJson(conn, { ok: false, error: "Control client not connected" });
      return;
    }
    if (data.type === "screenshot") {
      // Log size only — never screen content.
      const size = data.dataUrl ? String(data.dataUrl).length : 0;
      log("screenshot forwarded", "room=" + room.codeHash, "bytes=" + size);
    } else {
      log("forwarded", "room=" + room.codeHash, "type=" + data.type, "id=" + (data.id || "-"));
    }
    sendJson(peer, data);
    return;
  }

  if (data.type === "disconnect") {
    if (peer) sendJson(peer, { type: "disconnect", id: data.id || null });
    sendJson(conn, { ok: true, message: "Disconnected" });
    closeConn(conn, 1000, "disconnect requested");
    return;
  }

  sendJson(conn, { ok: false, error: "Unknown message type: " + data.type });
}

function handleWsFrame(conn, frame) {
  if (frame.opcode === 0x09) {
    // ping -> pong
    try { conn.socket.write(encodeFrame(frame.payload, 0x0a)); } catch (e) {}
    return;
  }
  if (frame.opcode === 0x0a) return; // pong, ignore
  if (frame.opcode === 0x08) {
    try { conn.socket.end(); } catch (e) {}
    return;
  }
  if (frame.opcode !== 0x01 && frame.opcode !== 0x02) {
    sendJson(conn, { ok: false, error: "Unsupported frame type" });
    return;
  }
  if (frame.payload.length > MAX_MESSAGE_BYTES) {
    sendJson(conn, { ok: false, error: "Message too large" });
    closeConn(conn, 1009, "message too large");
    return;
  }
  handleMessage(conn, frame.payload.toString("utf8"));
}

function detach(conn) {
  if (!conn.room || !conn.role) return;
  const room = conn.room;
  if (room[conn.role] === conn) room[conn.role] = null;
  const peer = peerOf(room, conn.role);
  if (peer) sendJson(peer, { type: "peer_disconnected", role: conn.role });
  log("client disconnected", "room=" + room.codeHash, "role=" + conn.role);
  cleanupRoom(conn.code);
}

// --- HTTP + upgrade --------------------------------------------------
const server = http.createServer((req, res) => {
  if (req.url === "/health") {
    const body = JSON.stringify({
      ok: true,
      service: "riya-laptop-assistant-relay",
      version: "1.0.0",
      uptimeSec: Math.floor(process.uptime()),
      rooms: rooms.size,
      connectedClients: [...rooms.values()].reduce((n, r) => n + (r.laptop ? 1 : 0) + (r.control ? 1 : 0), 0),
    });
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(body);
    return;
  }
  res.writeHead(200, { "Content-Type": "text/plain" });
  res.end("Riya Laptop Assistant relay. Connect with a WebSocket client and authenticate with your pairing code. GET /health for status.\n");
});

server.on("upgrade", (req, socket, head) => {
  const ip = (req.socket.remoteAddress || "unknown").replace(/^::ffff:/, "");
  const now = Date.now();
  const attempts = (ipAttempts.get(ip) || []).filter((t) => now - t < 60000);
  attempts.push(now);
  ipAttempts.set(ip, attempts);
  if (attempts.length > MAX_CONNECTIONS_PER_MIN_PER_IP) {
    log("connection rate-limited", "ip=" + ip);
    socket.destroy();
    return;
  }
  const key = req.headers["sec-websocket-key"];
  if (!key) {
    socket.destroy();
    return;
  }
  const accept = crypto.createHash("sha1").update(key + WS_GUID).digest("base64");
  socket.write(
    "HTTP/1.1 101 Switching Protocols\r\n" +
    "Upgrade: websocket\r\n" +
    "Connection: Upgrade\r\n" +
    "Sec-WebSocket-Accept: " + accept + "\r\n\r\n"
  );
  const conn = {
    socket,
    ip,
    authenticated: false,
    role: null,
    code: null,
    room: null,
    msgTimes: [],
    _wsBuf: Buffer.alloc(0),
    _frag: null,
    _fragOpcode: null,
  };
  log("ws connected", "ip=" + ip);
  sendJson(conn, { ok: true, type: "hello", message: "Riya relay. Send {\"type\":\"auth\",\"role\":\"laptop|control\",\"pairingCode\":\"RIYA-XXXXXX\"} first." });
  socket.on("data", (chunk) => {
    try {
      const frames = parseFrames(socket, chunk);
      for (const frame of frames) handleWsFrame(conn, frame);
    } catch (e) {
      log("frame error", "ip=" + ip, String(e.message));
      try { socket.destroy(); } catch (_) {}
    }
  });
  socket.on("close", () => detach(conn));
  socket.on("error", () => detach(conn));
});

server.listen(PORT, HOST, () => {
  log("listening on " + HOST + ":" + PORT, "health: /health, maxMessageBytes=" + MAX_MESSAGE_BYTES);
});

process.on("SIGINT", () => { log("shutting down"); server.close(() => process.exit(0)); });
process.on("SIGTERM", () => { log("shutting down"); server.close(() => process.exit(0)); });

module.exports = { validateCommand, PAIRING_CODE_RE };
