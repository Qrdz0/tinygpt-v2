const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const Database = require('better-sqlite3');
const path = require('path');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const { Readable } = require('stream');

const PORT = process.env.PORT || 3000;
const OLLAMA = process.env.OLLAMA_URL || 'http://localhost:11434';
const SESSION_SECRET = process.env.SESSION_SECRET || 'tinygpt-dev-secret-change-me';
const APP_BASE = process.env.APP_BASE_URL || 'http://localhost:' + PORT;
const BCRYPT_ROUNDS = 10;
const RESET_TTL_MS = 60 * 60 * 1000; // 1 hour

const db = new Database(path.join(__dirname, 'tinygpt.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE COLLATE NOCASE,
  password_hash TEXT NOT NULL,
  email TEXT,
  reset_token TEXT,
  reset_expiry TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  last_login_date TEXT,
  streak_count INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS login_days (
  user_id INTEGER NOT NULL REFERENCES users(id),
  date TEXT NOT NULL,
  PRIMARY KEY (user_id, date)
);
CREATE TABLE IF NOT EXISTS chats (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id),
  title TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  chat_id INTEGER NOT NULL REFERENCES chats(id) ON DELETE CASCADE,
  role TEXT NOT NULL,
  content TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
`);

// migrate pre-existing databases to the Phase 2.5 schema
const userCols = db.prepare('PRAGMA table_info(users)').all().map(c => c.name);
for (const col of ['email', 'reset_token', 'reset_expiry']) {
  if (!userCols.includes(col)) {
    db.exec(`ALTER TABLE users ADD COLUMN ${col} TEXT`);
  }
}
db.prepare('CREATE INDEX IF NOT EXISTS idx_users_reset_token ON users(reset_token)').run();

// Ethereal (fake SMTP) — logs a clickable preview URL for every email
let mailTransport = null;
async function getMailer() {
  if (mailTransport) return mailTransport;
  if (process.env.SMTP_HOST) {
    mailTransport = nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: Number(process.env.SMTP_PORT || 587),
      secure: process.env.SMTP_SECURE === 'true',
      auth: process.env.SMTP_USER
        ? { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
        : undefined
    });
  } else {
    const account = await nodemailer.createTestAccount();
    mailTransport = nodemailer.createTransport({
      host: account.smtp.host,
      port: account.smtp.port,
      secure: account.smtp.secure,
      auth: { user: account.user, pass: account.pass }
    });
  }
  return mailTransport;
}

async function sendMail({ to, subject, text, html }) {
  const transport = await getMailer();
  const info = await transport.sendMail({
    from: '"tinygpt v2" <no-reply@tinygpt.local>',
    to, subject, text, html
  });
  const preview = nodemailer.getTestMessageUrl(info);
  if (preview) {
    console.log('--------------------------------------------');
    console.log('[email] ' + subject);
    console.log('[email] Ethereal preview: ' + preview);
    console.log('--------------------------------------------');
  }
  return info;
}

// naive per-IP rate limit for the reset-request endpoint (memory only)
const resetAttempts = new Map();
function rateLimited(ip, max = 5, windowMs = 15 * 60 * 1000) {
  const now = Date.now();
  const entry = resetAttempts.get(ip) || { count: 0, start: now };
  if (now - entry.start > windowMs) {
    entry.count = 0;
    entry.start = now;
  }
  entry.count += 1;
  resetAttempts.set(ip, entry);
  return entry.count > max;
}

function dateStr(d = new Date()) {
  const y = d.getFullYear();
  const m = String(d.getMonth() + 1).padStart(2, '0');
  const day = String(d.getDate()).padStart(2, '0');
  return `${y}-${m}-${day}`;
}

function yesterdayStr() {
  const d = new Date();
  d.setDate(d.getDate() - 1);
  return dateStr(d);
}

function applyLogin(userId) {
  const today = dateStr();
  const user = db.prepare('SELECT last_login_date, streak_count FROM users WHERE id = ?').get(userId);
  let streak = user.streak_count;
  if (user.last_login_date === today) {
    streak = streak || 1;
  } else if (user.last_login_date === yesterdayStr()) {
    streak += 1;
  } else {
    streak = 1;
  }
  db.prepare('UPDATE users SET last_login_date = ?, streak_count = ? WHERE id = ?')
    .run(today, streak, userId);
  db.prepare('INSERT OR IGNORE INTO login_days (user_id, date) VALUES (?, ?)').run(userId, today);
  return streak;
}

const app = express();
app.use(express.json({ limit: '2mb' }));
app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', maxAge: 7 * 24 * 60 * 60 * 1000 }
}));

function requireAuth(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: 'Not logged in' });
  next();
}

function startSession(req, res, user, streak) {
  req.session.regenerate(err => {
    if (err) return res.status(500).json({ error: 'Could not create session' });
    req.session.userId = user.id;
    req.session.username = user.username;
    res.json({ id: user.id, username: user.username, streak });
  });
}

app.post('/api/register', async (req, res) => {
  const username = String(req.body.username || '').trim();
  const password = String(req.body.password || '');
  const email = String(req.body.email || '').trim();
  if (!/^[a-zA-Z0-9_]{3,32}$/.test(username)) {
    return res.status(400).json({ error: 'Username must be 3-32 letters, numbers or underscores' });
  }
  if (password.length < 6) {
    return res.status(400).json({ error: 'Password must be at least 6 characters' });
  }
  if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: 'Invalid email address' });
  }
  if (req.body.agree !== true) {
    return res.status(400).json({ error: 'You must agree to the Terms of Service and Privacy Policy' });
  }
  try {
    const hash = await bcrypt.hash(password, BCRYPT_ROUNDS);
    const info = db.prepare('INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)')
      .run(username, hash, email || null);
    const user = { id: info.lastInsertRowid, username };
    const streak = applyLogin(user.id);
    startSession(req, res, user, streak);
  } catch (e) {
    if (String(e.message).includes('UNIQUE')) {
      return res.status(409).json({ error: 'Username already taken' });
    }
    console.error(e);
    res.status(500).json({ error: 'Registration failed' });
  }
});

app.post('/api/login', async (req, res) => {
  const username = String(req.body.username || '').trim();
  const password = String(req.body.password || '');
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  const ok = user && (await bcrypt.compare(password, user.password_hash));
  if (!ok) return res.status(401).json({ error: 'Wrong username or password' });
  const streak = applyLogin(user.id);
  startSession(req, res, user, streak);
});

app.post('/api/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

const sha256 = s => crypto.createHash('sha256').update(s).digest('hex');

app.post('/api/forgot-password', async (req, res) => {
  const username = String(req.body.username || '').trim();
  const ip = req.ip || req.socket.remoteAddress || 'unknown';
  if (rateLimited(ip)) {
    return res.status(429).json({ error: 'Too many attempts. Try again in 15 minutes.' });
  }
  // always answer identically so usernames can't be probed
  const generic = { ok: true, message: 'If that account exists, a reset link has been emailed.' };
  try {
    const user = db.prepare('SELECT id, username, email FROM users WHERE username = ?').get(username);
    if (user) {
      const token = crypto.randomBytes(32).toString('hex'); // 256-bit, only leaves via email
      db.prepare('UPDATE users SET reset_token = ?, reset_expiry = ? WHERE id = ?')
        .run(sha256(token), new Date(Date.now() + RESET_TTL_MS).toISOString(), user.id);
      const resetUrl = APP_BASE + '/reset?token=' + token;
      await sendMail({
        to: user.email || user.username + '@users.tinygpt.local',
        subject: 'Reset your tinygpt password',
        text: 'Hello ' + user.username + ',\n\n' +
          'Use the link below to reset your password. It expires in 1 hour:\n' +
          resetUrl + '\n\n' +
          'If you did not request this, you can safely ignore this email.\n',
        html:
          '<div style="font-family:sans-serif;max-width:480px;margin:auto;padding:24px;background:#161b22;border:1px solid #30363d;border-radius:12px;color:#e6edf3">' +
          '<h2 style="color:#58a6ff;margin-top:0">tinygpt v2</h2>' +
          '<p>Hi ' + user.username + ',</p>' +
          '<p>We received a request to reset your password. This link expires in <b>1 hour</b>.</p>' +
          '<p style="text-align:center;margin:28px 0">' +
          '<a href="' + resetUrl + '" style="background:#238636;color:#fff;padding:12px 22px;border-radius:8px;text-decoration:none;font-weight:600">Reset password</a></p>' +
          '<p style="color:#8b949e;font-size:13px">If the button does not work, paste this URL into your browser:<br>' + resetUrl + '</p>' +
          '<p style="color:#8b949e;font-size:13px">If you did not request this, ignore this email. Your password will not change.</p>' +
          '</div>'
      });
    }
    res.json(generic);
  } catch (e) {
    console.error('[forgot-password]', e);
    res.json(generic);
  }
});

app.post('/api/reset-password', async (req, res) => {
  const token = String(req.body.token || '');
  const password = String(req.body.password || '');
  if (password.length < 6) {
    return res.status(400).json({ error: 'Password must be at least 6 characters' });
  }
  if (!/^[0-9a-f]{64}$/.test(token)) {
    return res.status(400).json({ error: 'Invalid or expired reset link' });
  }
  const user = db.prepare(
    'SELECT id, reset_expiry FROM users WHERE reset_token = ? AND reset_expiry IS NOT NULL'
  ).get(sha256(token));
  if (!user || Date.parse(user.reset_expiry) < Date.now()) {
    return res.status(400).json({ error: 'Invalid or expired reset link' });
  }
  const hash = await bcrypt.hash(password, BCRYPT_ROUNDS);
  // single-use: token cleared in the same statement that updates the password
  db.prepare('UPDATE users SET password_hash = ?, reset_token = NULL, reset_expiry = NULL WHERE id = ?')
    .run(hash, user.id);
  res.json({ ok: true, message: 'Password updated. You can log in now.' });
});

app.get('/api/me', requireAuth, (req, res) => {
  const user = db.prepare('SELECT id, username, streak_count, last_login_date FROM users WHERE id = ?')
    .get(req.session.userId);
  if (!user) return res.status(401).json({ error: 'Not logged in' });
  const days = db.prepare('SELECT date FROM login_days WHERE user_id = ? ORDER BY date DESC LIMIT 366')
    .all(user.id).map(r => r.date);
  res.json({
    id: user.id,
    username: user.username,
    streak: user.streak_count,
    lastLogin: user.last_login_date,
    days
  });
});

app.get('/api/chats', requireAuth, (req, res) => {
  const rows = db.prepare(
    'SELECT id, title, created_at, updated_at FROM chats WHERE user_id = ? ORDER BY updated_at DESC'
  ).all(req.session.userId);
  res.json(rows);
});

app.post('/api/chats', requireAuth, (req, res) => {
  const title = String(req.body.title || '').trim().slice(0, 80) || 'New chat';
  const info = db.prepare('INSERT INTO chats (user_id, title) VALUES (?, ?)')
    .run(req.session.userId, title);
  res.json({ id: info.lastInsertRowid, title });
});

function ownedChat(req, res) {
  const chat = db.prepare('SELECT * FROM chats WHERE id = ? AND user_id = ?')
    .get(req.params.id, req.session.userId);
  if (!chat) {
    res.status(404).json({ error: 'Chat not found' });
    return null;
  }
  return chat;
}

app.get('/api/chats/:id', requireAuth, (req, res) => {
  const chat = ownedChat(req, res);
  if (!chat) return;
  const messages = db.prepare('SELECT role, content FROM messages WHERE chat_id = ? ORDER BY id')
    .all(chat.id);
  res.json({ id: chat.id, title: chat.title, messages });
});

app.post('/api/chats/:id/messages', requireAuth, (req, res) => {
  const chat = ownedChat(req, res);
  if (!chat) return;
  const msgs = Array.isArray(req.body.messages) ? req.body.messages : [];
  const insert = db.prepare('INSERT INTO messages (chat_id, role, content) VALUES (?, ?, ?)');
  const touch = db.prepare("UPDATE chats SET updated_at = datetime('now') WHERE id = ?");
  const addAll = db.transaction(list => {
    for (const m of list) {
      const role = m.role === 'assistant' ? 'assistant' : 'user';
      const content = String(m.content || '');
      if (content) insert.run(chat.id, role, content.slice(0, 200000));
    }
    touch.run(chat.id);
  });
  addAll(msgs);
  res.json({ ok: true });
});

app.patch('/api/chats/:id', requireAuth, (req, res) => {
  const chat = ownedChat(req, res);
  if (!chat) return;
  const title = String(req.body.title || '').trim().slice(0, 80);
  if (!title) return res.status(400).json({ error: 'Title required' });
  db.prepare("UPDATE chats SET title = ?, updated_at = datetime('now') WHERE id = ?").run(title, chat.id);
  res.json({ ok: true });
});

app.delete('/api/chats/:id', requireAuth, (req, res) => {
  const chat = ownedChat(req, res);
  if (!chat) return;
  db.prepare('DELETE FROM chats WHERE id = ?').run(chat.id);
  res.json({ ok: true });
});

app.post('/api/ollama/chat', requireAuth, async (req, res) => {
  try {
    const payload = Object.assign({}, req.body, { stream: true });
    const up = await fetch(OLLAMA + '/api/chat', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    if (!up.ok) {
      const text = await up.text();
      return res.status(up.status).json({ error: text || 'Ollama error' });
    }
    res.writeHead(200, { 'Content-Type': 'application/x-ndjson' });
    Readable.fromWeb(up.body).pipe(res);
  } catch (e) {
    res.status(502).json({ error: 'Cannot reach Ollama. Is "ollama serve" running?' });
  }
});

app.get('/api/ollama/models', requireAuth, async (req, res) => {
  try {
    const up = await fetch(OLLAMA + '/api/tags');
    const data = await up.text();
    res.writeHead(up.status, { 'Content-Type': 'application/json' });
    res.end(data);
  } catch (e) {
    res.status(502).json({ error: 'Cannot reach Ollama' });
  }
});

const pageRoutes = { '/terms': 'terms.html', '/privacy': 'privacy.html', '/reset': 'reset.html', '/forgot': 'forgot.html' };
for (const [route, file] of Object.entries(pageRoutes)) {
  app.get(route, (req, res) => res.sendFile(path.join(__dirname, 'public', file)));
}

app.use(express.static(path.join(__dirname, 'public')));

app.listen(PORT, () => {
  console.log('tinygpt-v2 backend at http://localhost:' + PORT);
  console.log('proxying Ollama at ' + OLLAMA);
});
