const path = require("node:path");
const crypto = require("node:crypto");
const fs = require("node:fs");
const express = require("express");
const helmet = require("helmet");
const cookieParser = require("cookie-parser");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcryptjs");
const Database = require("better-sqlite3");

const app = express();
const PORT = Number(process.env.PORT || 3000);
const SESSION_SECRET = process.env.SESSION_SECRET || "development-only-change-before-production";
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, "data");
fs.mkdirSync(DATA_DIR, { recursive: true });
const db = new Database(path.join(DATA_DIR, "saas.sqlite"));
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    status TEXT NOT NULL DEFAULT 'pending',
    expires_at TEXT,
    coins INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    expires_at TEXT NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
  );
  CREATE TABLE IF NOT EXISTS predictions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    input TEXT NOT NULL,
    candidates TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
  );
  CREATE TABLE IF NOT EXISTS coin_ledger (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    amount INTEGER NOT NULL,
    reason TEXT NOT NULL,
    created_by INTEGER,
    created_at TEXT NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
  );
  CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_id INTEGER,
    action TEXT NOT NULL,
    details TEXT,
    created_at TEXT NOT NULL
  );
`);

app.set("trust proxy", 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "32kb" }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public")));

const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 20, standardHeaders: true, legacyHeaders: false });

function clean(value, max = 120) {
  return String(value ?? "").trim().slice(0, max);
}

function now() { return new Date().toISOString(); }
function cookieOptions() {
  return { httpOnly: true, secure: process.env.NODE_ENV === "production", sameSite: "lax", maxAge: 7 * 24 * 60 * 60 * 1000 };
}
function audit(actorId, action, details = "") {
  db.prepare("INSERT INTO audit_logs(actor_id, action, details, created_at) VALUES (?, ?, ?, ?)").run(actorId, action, details.slice(0, 500), now());
}
function isActive(user) {
  return user.status === "active" && (!user.expires_at || new Date(`${user.expires_at}T23:59:59`) >= new Date());
}

function requireAuth(req, res, next) {
  const token = req.cookies?.session;
  const session = token && db.prepare("SELECT * FROM sessions WHERE token = ?").get(token);
  if (!session || new Date(session.expires_at) <= new Date()) {
    return res.status(401).json({ error: "Please log in again." });
  }
  const user = db.prepare("SELECT * FROM users WHERE id = ?").get(session.user_id);
  if (!user || !isActive(user)) return res.status(403).json({ error: "Account access is inactive or expired." });
  req.user = user;
  next();
}

function requireAdmin(req, res, next) {
  if (!["owner", "ceo", "admin"].includes(req.user.role)) return res.status(403).json({ error: "Admin permission required." });
  next();
}

function ownerEmail() { return clean(process.env.OWNER_EMAIL || "owner@bigsmall.local").toLowerCase(); }
async function seedOwner() {
  if (!db.prepare("SELECT 1 FROM users WHERE role = ?").get("owner")) {
    const password = process.env.OWNER_PASSWORD || "ChangeMeNow123!";
    db.prepare("INSERT INTO users(name,email,password_hash,role,status,expires_at,coins,created_at) VALUES (?, ?, ?, 'owner', 'active', '2099-12-31', 0, ?)")
      .run("Owner", ownerEmail(), await bcrypt.hash(password, 12), now());
  }
}

function normalizeScores(values) {
  const total = values.reduce((sum, value) => sum + value, 0);
  return values.map((value) => value / total);
}

function adaptivePrediction(history) {
  const frequency = Array(10).fill(0);
  history.forEach((number) => frequency[number]++);
  const recent = Array(10).fill(0);
  history.slice(-30).forEach((number, index, values) => recent[number] += 1 + index / values.length);
  const combined = normalizeScores(frequency.map((value, index) => value + recent[index] * 0.75 + 0.5));
  return combined.map((score, number) => ({ number, score })).sort((a, b) => b.score - a.score || a.number - b.number);
}

function parseHistory(value) {
  const tokens = String(value || "").split(/[\s,;|]+/).map(clean).filter(Boolean);
  if (tokens.length > 1000) throw new Error("Maximum history is 1000 results.");
  if (tokens.some((token) => !/^\d$/.test(token))) throw new Error("Only numbers 0 to 9 are allowed.");
  return tokens.map(Number);
}

app.post("/api/auth/signup", authLimiter, async (req, res) => {
  try {
    const name = clean(req.body.name, 80);
    const email = clean(req.body.email, 160).toLowerCase();
    const password = String(req.body.password || "");
    if (name.length < 2) return res.status(400).json({ error: "Name must be at least 2 characters." });
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: "Enter a valid email." });
    if (password.length < 10) return res.status(400).json({ error: "Password must be at least 10 characters." });
    if (db.prepare("SELECT id FROM users WHERE email = ? COLLATE NOCASE").get(email)) return res.status(409).json({ error: "Email is already registered." });
    const hash = await bcrypt.hash(password, 12);
    const result = db.prepare("INSERT INTO users(name,email,password_hash,role,status,coins,created_at) VALUES (?, ?, ?, 'user', 'pending', 0, ?)")
      .run(name, email, hash, now());
    audit(result.lastInsertRowid, "signup", email);
    res.status(201).json({ message: "Account created. Manual access approval is required." });
  } catch {
    res.status(500).json({ error: "Unable to create account." });
  }
});

app.post("/api/auth/login", authLimiter, async (req, res) => {
  const email = clean(req.body.email, 160).toLowerCase();
  const password = String(req.body.password || "");
  const user = db.prepare("SELECT * FROM users WHERE email = ? COLLATE NOCASE").get(email);
  if (!user || !(await bcrypt.compare(password, user.password_hash))) return res.status(401).json({ error: "Invalid email or password." });
  if (!["owner", "ceo", "admin"].includes(user.role) && !isActive(user)) return res.status(403).json({ error: "Account access is pending, disabled, or expired." });
  db.prepare("DELETE FROM sessions WHERE user_id = ?").run(user.id);
  const token = crypto.randomBytes(32).toString("hex");
  db.prepare("INSERT INTO sessions(token,user_id,expires_at) VALUES (?, ?, ?)").run(token, user.id, new Date(Date.now() + 7 * 86400000).toISOString());
  res.cookie("session", token, cookieOptions());
  audit(user.id, "login", "Successful login");
  res.json({ user: { id: user.id, name: user.name, email: user.email, role: user.role } });
});

app.post("/api/auth/logout", requireAuth, (req, res) => {
  db.prepare("DELETE FROM sessions WHERE token = ?").run(req.cookies.session);
  res.clearCookie("session");
  res.json({ ok: true });
});

app.get("/api/me", requireAuth, (req, res) => {
  res.json({ user: { id: req.user.id, name: req.user.name, email: req.user.email, role: req.user.role, coins: req.user.coins, expires_at: req.user.expires_at } });
});

app.post("/api/predict", requireAuth, (req, res) => {
  let history;
  try { history = parseHistory(req.body.history); } catch (error) { return res.status(400).json({ error: error.message }); }
  if (history.length < 3) return res.status(400).json({ error: "Enter at least 3 past results." });
  const candidates = adaptivePrediction(history);
  db.prepare("INSERT INTO predictions(user_id,input,candidates,created_at) VALUES (?, ?, ?, ?)").run(req.user.id, JSON.stringify(history), JSON.stringify(candidates.slice(0, 3)), now());
  res.json({ candidates: candidates.slice(0, 3), disclaimer: "Predictions are statistical rankings, not guaranteed outcomes." });
});

app.get("/api/predictions", requireAuth, (req, res) => {
  const rows = db.prepare("SELECT id,candidates,created_at FROM predictions WHERE user_id=? ORDER BY id DESC LIMIT 50").all(req.user.id);
  res.json({ predictions: rows.map((row) => ({ ...row, candidates: JSON.parse(row.candidates) })) });
});

app.get("/api/admin/overview", requireAuth, requireAdmin, (req, res) => {
  const users = db.prepare("SELECT COUNT(*) count FROM users WHERE role='user'").get().count;
  const active = db.prepare("SELECT COUNT(*) count FROM users WHERE role='user' AND status='active'").get().count;
  const pending = db.prepare("SELECT COUNT(*) count FROM users WHERE role='user' AND status='pending'").get().count;
  const predictions = db.prepare("SELECT COUNT(*) count FROM predictions").get().count;
  res.json({ users, active, pending, predictions });
});

app.get("/api/admin/users", requireAuth, requireAdmin, (req, res) => {
  const search = `%${clean(req.query.search, 80)}%`;
  const users = db.prepare("SELECT id,name,email,role,status,expires_at,coins,created_at FROM users WHERE role='user' AND (name LIKE ? ESCAPE '\\' OR email LIKE ? ESCAPE '\\') ORDER BY id DESC LIMIT 200")
    .all(search, search);
  res.json({ users });
});

app.patch("/api/admin/users/:id", requireAuth, requireAdmin, (req, res) => {
  const target = db.prepare("SELECT * FROM users WHERE id=? AND role='user'").get(req.params.id);
  if (!target) return res.status(404).json({ error: "User not found." });
  if (!["pending", "active", "disabled"].includes(req.body.status || target.status)) return res.status(400).json({ error: "Invalid status." });
  const expiresAt = req.body.expires_at === undefined ? target.expires_at : clean(req.body.expires_at, 10) || null;
  db.prepare("UPDATE users SET status=?, expires_at=? WHERE id=?").run(req.body.status || target.status, expiresAt, target.id);
  audit(req.user.id, "update_user_access", JSON.stringify({ target: target.id, status: req.body.status || target.status, expires_at: expiresAt }));
  res.json({ ok: true });
});

app.post("/api/admin/users/:id/coins", requireAuth, requireAdmin, (req, res) => {
  const amount = Number(req.body.amount);
  if (!Number.isInteger(amount) || amount === 0 || Math.abs(amount) > 1000000) return res.status(400).json({ error: "Enter a valid coin adjustment." });
  const target = db.prepare("SELECT * FROM users WHERE id=?").get(req.params.id);
  if (!target || target.role !== "user") return res.status(404).json({ error: "User not found." });
  if (target.coins + amount < 0) return res.status(400).json({ error: "Adjustment would create a negative balance." });
  const transaction = db.transaction(() => {
    db.prepare("UPDATE users SET coins=coins+? WHERE id=?").run(amount, target.id);
    db.prepare("INSERT INTO coin_ledger(user_id,amount,reason,created_by,created_at) VALUES (?, ?, ?, ?, ?)").run(target.id, amount, clean(req.body.reason, 200) || "Manual admin adjustment", req.user.id, now());
  });
  transaction();
  audit(req.user.id, "adjust_coins", JSON.stringify({ target: target.id, amount }));
  res.json({ ok: true });
});

app.get("/api/admin/audit", requireAuth, requireAdmin, (req, res) => {
  res.json({ logs: db.prepare("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 100").all() });
});

app.get("/api/health", (req, res) => res.json({ status: "ok", time: now() }));
app.get("/admin", (req, res) => res.sendFile(path.join(__dirname, "public", "admin.html")));
app.use((req, res) => res.status(404).json({ error: "Not found." }));
app.use((error, req, res, next) => {
  console.error(error);
  res.status(500).json({ error: "Unexpected server error." });
});

seedOwner().then(() => app.listen(PORT, () => console.log(`BigSmall Predictor SaaS running on http://localhost:${PORT}`)));
