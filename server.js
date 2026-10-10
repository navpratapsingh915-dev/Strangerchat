const express = require('express');
const http = require('http');
const path = require('path');
const { WebSocketServer } = require('ws');

const PORT = process.env.PORT || 3000;
const MAX_MSG_LEN = 500;
const RATE_LIMIT_COUNT = 5;
const RATE_LIMIT_WINDOW = 5000;
const REPORTS_TO_BAN = 3;
const BAN_MS = 60 * 60 * 1000;

const BLOCKED_WORDS = ['badword1', 'badword2'];

const app = express();
app.use(express.static(path.join(__dirname, 'public')));
const server = http.createServer(app);
const wss = new WebSocketServer({ server });

const waiting = [];
const reportCounts = new Map();
const bans = new Map();

function getIp(req) {
  const fwd = req.headers['x-forwarded-for'];
  return fwd ? fwd.split(',')[0].trim() : req.socket.remoteAddress;
}

function isBanned(ip) {
  const until = bans.get(ip);
  if (!until) return false;
  if (Date.now() > until) {
    bans.delete(ip);
    reportCounts.delete(ip);
    return false;
  }
  return true;
}

function send(ws, obj) {
  if (ws.readyState === ws.OPEN) ws.send(JSON.stringify(obj));
}

function broadcastOnline() {
  const n = wss.clients.size;
  for (const c of wss.clients) send(c, { type: 'online', count: n });
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
    send(ws, { type: 'matched' });
    send(other, { type: 'matched' });
    return;
  }
  waiting.push(ws);
  send(ws, { type: 'waiting' });
}

wss.on('connection', (ws, req) => {
  ws.ip = getIp(req);
  ws.partner = null;
  ws.msgTimes = [];
  ws.adultConfirmed = false;

  if (isBanned(ws.ip)) {
    send(ws, { type: 'banned' });
    ws.close();
    return;
  }

  broadcastOnline();

  ws.on('message', (raw) => {
    let data;
    try {
      data = JSON.parse(raw);
    } catch {
      return;
    }

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
        if (!ws.partner) return;
        const now = Date.now();
        ws.msgTimes = ws.msgTimes.filter((t) => now - t < RATE_LIMIT_WINDOW);
        if (ws.msgTimes.length >= RATE_LIMIT_COUNT) {
          return send(ws, { type: 'error', message: 'Slow down, you are sending too fast.' });
        }
        ws.msgTimes.push(now);
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
        const target = ws.partner ? ws.partner.ip : ws.lastPartnerIp;
        if (!target) return;
        const count = (reportCounts.get(target) || 0) + 1;
        reportCounts.set(target, count);
        if (count >= REPORTS_TO_BAN) {
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
  });

  ws.on('close', () => {
    removeFromQueue(ws);
    disconnectPair(ws);
    broadcastOnline();
  });
});

server.listen(PORT, () => console.log(`Running on http://localhost:${PORT}`));
