const Database = require('better-sqlite3');
const path = require('path');
const crypto = require('crypto');

const DB_PATH = process.env.VERCEL ? path.join('/tmp', 'webguard.db') : path.join(__dirname, 'webguard.db');
const db = new Database(DB_PATH);

db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    email             TEXT    UNIQUE NOT NULL,
    password          TEXT    NOT NULL,
    name              TEXT    NOT NULL,
    role              TEXT    NOT NULL DEFAULT 'analyst',
    totp_secret       TEXT,
    totp_enabled      INTEGER NOT NULL DEFAULT 0,
    recovery_key_hash TEXT,
    created_at        TEXT    NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS api_keys (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    key_hash   TEXT    UNIQUE NOT NULL,
    key_prefix TEXT    NOT NULL,
    label      TEXT    NOT NULL DEFAULT 'Default Key',
    created_at TEXT    NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS scans (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER REFERENCES users(id) ON DELETE SET NULL,
    domain     TEXT    NOT NULL,
    score      INTEGER NOT NULL,
    grade      TEXT    NOT NULL,
    findings   TEXT    NOT NULL,
    created_at TEXT    NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS integration_settings (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         INTEGER NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    slack_webhook   TEXT,
    jira_url        TEXT,
    jira_email      TEXT,
    jira_token      TEXT,
    jira_project    TEXT,
    webhook_url     TEXT,
    whitelabel_name TEXT,
    whitelabel_logo TEXT,
    gemini_api_key  TEXT,
    updated_at      TEXT    NOT NULL DEFAULT (datetime('now'))
  );
`);

// ─── Migrations: safely add columns to existing databases ─────────────────
try { db.prepare(`ALTER TABLE users ADD COLUMN recovery_key_hash TEXT`).run(); } catch (e) { /* column already exists */ }
try { db.prepare(`ALTER TABLE integration_settings ADD COLUMN gemini_api_key TEXT`).run(); } catch (e) { /* column already exists */ }

// ─── User Functions ────────────────────────────────────────────────────────
function createUser(email, passwordHash, name, role = 'analyst') {
  return db.prepare(`INSERT INTO users (email, password, name, role) VALUES (?, ?, ?, ?)`).run(email, passwordHash, name, role);
}
function getUserByEmail(email) {
  return db.prepare(`SELECT * FROM users WHERE email = ?`).get(email);
}
function getUserById(id) {
  return db.prepare(`SELECT id, email, name, role, totp_enabled, created_at FROM users WHERE id = ?`).get(id);
}
function updateUserTOTP(userId, secret, enabled) {
  db.prepare(`UPDATE users SET totp_secret = ?, totp_enabled = ? WHERE id = ?`).run(secret, enabled ? 1 : 0, userId);
}
function getAllUsers() {
  return db.prepare(`SELECT id, email, name, role, totp_enabled, created_at FROM users ORDER BY created_at DESC`).all();
}

// Recovery Key Functions
function setRecoveryKey(userId, rawKey) {
  const hash = crypto.createHash('sha256').update(rawKey).digest('hex');
  db.prepare(`UPDATE users SET recovery_key_hash = ? WHERE id = ?`).run(hash, userId);
}
function resetPasswordWithKey(email, rawKey, newPasswordHash) {
  const user = db.prepare(`SELECT * FROM users WHERE email = ?`).get(email);
  if (!user || !user.recovery_key_hash) return false;
  const hash = crypto.createHash('sha256').update(rawKey).digest('hex');
  if (hash !== user.recovery_key_hash) return false;
  // Valid — update password and invalidate the recovery key so it can only be used once
  db.prepare(`UPDATE users SET password = ?, recovery_key_hash = NULL WHERE id = ?`).run(newPasswordHash, user.id);
  return true;
}

// ─── API Key Functions ─────────────────────────────────────────────────────
function generateApiKey(userId, label = 'Default Key') {
  const rawKey = 'wg_' + crypto.randomBytes(28).toString('hex');
  const hash = crypto.createHash('sha256').update(rawKey).digest('hex');
  const prefix = rawKey.slice(0, 10);
  db.prepare(`DELETE FROM api_keys WHERE user_id = ?`).run(userId);
  db.prepare(`INSERT INTO api_keys (user_id, key_hash, key_prefix, label) VALUES (?, ?, ?, ?)`).run(userId, hash, prefix, label);
  return rawKey;
}
function getApiKeyInfo(rawKey) {
  const hash = crypto.createHash('sha256').update(rawKey).digest('hex');
  return db.prepare(`SELECT ak.*, u.id as uid, u.email, u.role FROM api_keys ak JOIN users u ON ak.user_id = u.id WHERE ak.key_hash = ?`).get(hash) || null;
}
function getApiKeyForUser(userId) {
  return db.prepare(`SELECT key_prefix, label, created_at FROM api_keys WHERE user_id = ?`).get(userId);
}

// ─── Scan History Functions ────────────────────────────────────────────────
function saveScan(userId, domain, score, grade, findings) {
  const json = typeof findings === 'string' ? findings : JSON.stringify(findings);
  return db.prepare(`INSERT INTO scans (user_id, domain, score, grade, findings) VALUES (?, ?, ?, ?, ?)`).run(userId || null, domain, score, grade, json);
}
function getScanHistory(userId, limit = 50) {
  return db.prepare(`SELECT id, domain, score, grade, created_at FROM scans WHERE user_id = ? ORDER BY created_at DESC LIMIT ?`).all(userId, limit);
}
function getScansByDomain(userId, domain, limit = 30) {
  return db.prepare(`SELECT id, domain, score, grade, created_at FROM scans WHERE user_id = ? AND domain = ? ORDER BY created_at DESC LIMIT ?`).all(userId, domain, limit);
}
function getAllDomainsForUser(userId) {
  return db.prepare(`SELECT DISTINCT domain FROM scans WHERE user_id = ? ORDER BY domain`).all(userId);
}
function getLatestScanPerDomain(userId) {
  return db.prepare(`
    SELECT s.domain, s.score, s.grade, s.created_at
    FROM scans s
    INNER JOIN (SELECT domain, MAX(id) as max_id FROM scans WHERE user_id = ? GROUP BY domain) latest
    ON s.id = latest.max_id ORDER BY s.score ASC
  `).all(userId);
}

// ─── Integration Settings ──────────────────────────────────────────────────
function getSettings(userId) {
  return db.prepare(`SELECT * FROM integration_settings WHERE user_id = ?`).get(userId) || {};
}
function getGeminiKey(userId) {
  const row = db.prepare(`SELECT gemini_api_key FROM integration_settings WHERE user_id = ?`).get(userId);
  return (row && row.gemini_api_key) ? row.gemini_api_key : null;
}
function saveSettings(userId, s) {
  const exists = db.prepare(`SELECT id FROM integration_settings WHERE user_id = ?`).get(userId);
  if (exists) {
    db.prepare(`UPDATE integration_settings SET slack_webhook=?,jira_url=?,jira_email=?,jira_token=?,jira_project=?,webhook_url=?,whitelabel_name=?,whitelabel_logo=?,gemini_api_key=?,updated_at=datetime('now') WHERE user_id=?`)
      .run(s.slack_webhook||null,s.jira_url||null,s.jira_email||null,s.jira_token||null,s.jira_project||null,s.webhook_url||null,s.whitelabel_name||null,s.whitelabel_logo||null,s.gemini_api_key||null,userId);
  } else {
    db.prepare(`INSERT INTO integration_settings (user_id,slack_webhook,jira_url,jira_email,jira_token,jira_project,webhook_url,whitelabel_name,whitelabel_logo,gemini_api_key) VALUES (?,?,?,?,?,?,?,?,?,?)`)
      .run(userId,s.slack_webhook||null,s.jira_url||null,s.jira_email||null,s.jira_token||null,s.jira_project||null,s.webhook_url||null,s.whitelabel_name||null,s.whitelabel_logo||null,s.gemini_api_key||null);
  }
}

module.exports = {
  createUser, getUserByEmail, getUserById, updateUserTOTP, getAllUsers,
  setRecoveryKey, resetPasswordWithKey,
  generateApiKey, getApiKeyInfo, getApiKeyForUser,
  saveScan, getScanHistory, getScansByDomain, getAllDomainsForUser, getLatestScanPerDomain,
  getSettings, saveSettings, getGeminiKey
};
