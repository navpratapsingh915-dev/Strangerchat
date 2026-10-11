const express = require('express');
const http = require('http');
const path = require('path');
const { WebSocketServer } = require('ws');

const PORT = process.env.PORT || 3000;
const MAX_MSG_LEN = 500;
const MAX_PAYLOAD = 2048;            // bytes per websocket message
const MAX_CONN_PER_IP = 5;           // open connections per IP
const CONN_ATTEMPTS_PER_MIN = 20;    // new connections per IP per minute
const MSG_LIMIT = 5;                 // chat messages
const MSG_WINDOW = 5000;             // per 5 seconds
const ANY_LIMIT = 30;                // any packets
const ANY_WINDOW = 5000;             // per 5 seconds, else disconnect
const REPORTS_TO_BAN = 3;            // different people reporting
const MAX_REPORTS_PER_SOCKET = 5;
const BAN_MS = 60 * 60 * 1000;

// Replace/extend with a proper word list
const BLOCKED_WORDS = require('./words');

const app = express();
app.disable('x-powered-by');
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Strict-Transport-Security', 'max-age=15552000; includeSubDomains');
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self' wss: ws:; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
  );
  next();
});
app.use(express.static(path.join(__dirname, 'public'), { dotfiles: 'ignore', index: 'index.html' }));

const server = http.createServer(app);
server.headersTimeout = 15000;
server.requestTimeout = 15000;

// Only accept websocket connections coming from our own website
function verifyClient(info) {
  const origin = info.origin;
  if (!origin) return false;
  try {
    return new URL(origin).host === info.req.headers.host;
  } catch {
    return false;
  }
}

const wss = new WebSocketServer({ server, maxPayload: MAX_PAYLOAD, verifyClient });

const waiting = [];
const reports = new Map();      // target ip -> { reporters:Set, ts }
const bans = new Map();         // ip -> expiry
const connCount = new Map();    // ip -> open connections
const connAttempts = new Map(); // ip -> [timestamps]

function getIp(req) {
  // Render adds the real client IP as the LAST entry; earlier entries can be faked
  const fwd = req.headers['x-forwarded-for'];
  if (fwd) {
    const parts = String(fwd).split(',');
    return parts[parts.length - 1].trim();
  }
  return req.socket.remoteAddress;
}

function isBanned(ip) {
  const until = bans.get(ip);
  if (!until) return false;
  if (Date.now() > until) {
    bans.delete(ip);
    reports.delete(ip);
    return false;
  }
  return true;
}

function send(ws, obj) {
  if (ws.readyState === ws.OPEN) ws.send(JSON.stringify(obj));
}

// Online count: send at most every 2 seconds
let broadcastTimer = null;
function scheduleOnlineBroadcast() {
  if (broadcastTimer) return;
  broadcastTimer = setTimeout(() => {
    broadcastTimer = null;
    const n = wss.clients.size;
    for (const c of wss.clients) send(c, { type: 'online', count: n });
  }, 2000);
}

function cleanText(text) {
  let t = String(text).replace(/[\u0000-\u001f\u007f]/g, ' ').trim().slice(0, MAX_MSG_LEN);
  for (const w of BLOCKED_WORDS) {
    const re = new RegExp(w.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'gi');
    t = t.replace(re, '*'.repeat(w.length));
  }
  return t;
}

function removeFromQueue(ws) {
  const i = waiting.indexOf(ws);
  if (i !== -1) waiting.splice(i, 1);
}

function disconnectPair(ws, notify = true) {
  const partner = ws.partner;
  if (partner) {
    partner.lastPartnerIp = ws.ip;
    ws.lastPartnerIp = partner.ip;
    partner.partner = null;
    ws.partner = null;
    if (notify) send(partner, { type: 'partner_left' });
  }
}

function findPartner(ws) {
  if (ws.partner || waiting.includes(ws)) return;
  while (waiting.length) {
    const other = waiting.shift();
    if (other.readyState !== other.OPEN || other === ws) continue;
    ws.partner = other;
    other.partner = ws;
    ws.lastPartnerIp = other.ip;
    other.lastPartnerIp = ws.ip;
    send(ws, { type: 'matched' });
    send(other, { type: 'matched' });
    return;
  }
  waiting.push(ws);
  send(ws, { type: 'waiting' });
}

wss.on('connection', (ws, req) => {
  const ip = getIp(req);
  ws.ip = ip;
  ws.partner = null;
  ws.lastPartnerIp = null;
  ws.msgTimes = [];
  ws.anyTimes = [];
  ws.reportsMade = 0;
  ws.adultConfirmed = false;
  ws.isAlive = true;

  const now = Date.now();
  const attempts = (connAttempts.get(ip) || []).filter((t) => now - t < 60000);
  attempts.push(now);
  connAttempts.set(ip, attempts);

  if (isBanned(ip) || attempts.length > CONN_ATTEMPTS_PER_MIN || (connCount.get(ip) || 0) >= MAX_CONN_PER_IP) {
    send(ws, { type: 'banned' });
    ws.close();
    return;
  }
  connCount.set(ip, (connCount.get(ip) || 0) + 1);
  ws.counted = true;

  scheduleOnlineBroadcast();

  ws.on('pong', () => { ws.isAlive = true; });
  ws.on('error', () => {});

  ws.on('message', (raw) => {
    try {
      const t = Date.now();
      ws.anyTimes = ws.anyTimes.filter((x) => t - x < ANY_WINDOW);
      ws.anyTimes.push(t);
      if (ws.anyTimes.length > ANY_LIMIT) {
        ws.close();
        return;
      }

      let data;
      try {
        data = JSON.parse(raw);
      } catch {
        return;
      }
      if (!data || typeof data !== 'object' || typeof data.type !== 'string') return;

      switch (data.type) {
        case 'confirm_age':
          ws.adultConfirmed = data.over18 === true;
          break;

        case 'find':
          if (!ws.adultConfirmed) return send(ws, { type: 'error', message: 'You must confirm you are 18+.' });
          disconnectPair(ws);
          removeFromQueue(ws);
          findPartner(ws);
          break;

        case 'msg': {
          if (!ws.partner || typeof data.text !== 'string') return;
          ws.msgTimes = ws.msgTimes.filter((x) => t - x < MSG_WINDOW);
          if (ws.msgTimes.length >= MSG_LIMIT) {
            return send(ws, { type: 'error', message: 'Slow down, you are sending too fast.' });
          }
          ws.msgTimes.push(t);
          const text = cleanText(data.text);
          if (!text) return;
          send(ws.partner, { type: 'msg', text });
          break;
        }

        case 'typing':
          if (ws.partner) send(ws.partner, { type: 'typing' });
          break;

        case 'skip':
          disconnectPair(ws);
          removeFromQueue(ws);
          send(ws, { type: 'idle' });
          break;

        case 'report': {
          const target = ws.lastPartnerIp;
          ws.lastPartnerIp = null; // each stranger can be reported only once per chat
          if (!target || target === ws.ip) return;
          if (++ws.reportsMade > MAX_REPORTS_PER_SOCKET) return;
          let rec = reports.get(target);
          if (!rec) {
            rec = { reporters: new Set(), ts: Date.now() };
            reports.set(target, rec);
          }
          rec.reporters.add(ws.ip); // same reporter IP counts only once
          if (rec.reporters.size >= REPORTS_TO_BAN) {
            bans.set(target, Date.now() + BAN_MS);
            for (const c of wss.clients) {
              if (c.ip === target) {
                send(c, { type: 'banned' });
                c.close();
              }
            }
          }
          send(ws, { type: 'reported' });
          break;
        }
      }
    } catch (e) {
      console.error('handler error', e && e.message);
    }
  });

  ws.on('close', () => {
    removeFromQueue(ws);
    disconnectPair(ws);
    if (ws.counted) {
      const n = (connCount.get(ws.ip) || 1) - 1;
      if (n <= 0) connCount.delete(ws.ip);
      else connCount.set(ws.ip, n);
    }
    scheduleOnlineBroadcast();
  });
});

// Drop dead connections
setInterval(() => {
  for (const c of wss.clients) {
    if (!c.isAlive) { c.terminate(); continue; }
    c.isAlive = false;
    try { c.ping(); } catch {}
  }
}, 30000);

// Clean old data so memory does not grow forever
setInterval(() => {
  const now = Date.now();
  for (const [ip, until] of bans) if (now > until) { bans.delete(ip); reports.delete(ip); }
  for (const [ip, rec] of reports) if (now - rec.ts > BAN_MS) reports.delete(ip);
  for (const [ip, arr] of connAttempts) {
    if (!arr.some((t) => now - t < 60000)) connAttempts.delete(ip);
  }
}, 10 * 60 * 1000);

process.on('uncaughtException', (e) => console.error('uncaught', e && e.message));
process.on('unhandledRejection', (e) => console.error('unhandled', e && e.message));

server.listen(PORT, () => console.log(`Running on http://localhost:${PORT}`));
