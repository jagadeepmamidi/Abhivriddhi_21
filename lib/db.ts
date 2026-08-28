import fs from "node:fs";
import path from "node:path";
import { randomUUID } from "node:crypto";
import Database from "better-sqlite3";
import bcrypt from "bcryptjs";

const DATA_DIR = process.env.DATA_DIR || path.join(process.cwd(), "data");

let db: Database.Database | null = null;

export type UserRow = {
  id: string;
  username: string;
  email: string;
  password_hash: string;
  created_at: string;
};

export type AuditRow = {
  id: string;
  user_id: string;
  action: string;
  data_hash: string;
  method: string | null;
  redaction_level: string | null;
  encryption_used: number;
  domain: string | null;
  entity_types: string | null;
  previous_hash: string;
  chain_hash: string;
  created_at: string;
};

export type DownloadRow = {
  id: string;
  user_id: string;
  filename: string;
  mime: string;
  content: Buffer;
  created_at: string;
};

function ensureDir(dir: string) {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

export function getDb(): Database.Database {
  if (db) return db;
  ensureDir(DATA_DIR);
  const file = path.join(DATA_DIR, "redact.db");
  db = new Database(file);
  db.pragma("journal_mode = WAL");
  db.pragma("foreign_keys = ON");
  migrate(db);
  seedDemoUser(db);
  return db;
}

function migrate(database: Database.Database) {
  database.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      username TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS audit_logs (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      action TEXT NOT NULL,
      data_hash TEXT NOT NULL,
      method TEXT,
      redaction_level TEXT,
      encryption_used INTEGER NOT NULL DEFAULT 0,
      domain TEXT,
      entity_types TEXT,
      previous_hash TEXT NOT NULL,
      chain_hash TEXT NOT NULL,
      created_at TEXT NOT NULL,
      FOREIGN KEY (user_id) REFERENCES users(id)
    );
    CREATE TABLE IF NOT EXISTS downloads (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      filename TEXT NOT NULL,
      mime TEXT NOT NULL,
      content BLOB NOT NULL,
      created_at TEXT NOT NULL,
      FOREIGN KEY (user_id) REFERENCES users(id)
    );
    CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_logs(user_id, created_at);
    CREATE INDEX IF NOT EXISTS idx_downloads_user ON downloads(user_id, created_at);
  `);
}

function seedDemoUser(database: Database.Database) {
  const existing = database.prepare("SELECT id FROM users WHERE email = ?").get("demo@redact.app");
  if (existing) return;
  database
    .prepare(
      "INSERT INTO users (id, username, email, password_hash, created_at) VALUES (?, ?, ?, ?, ?)",
    )
    .run(
      randomUUID(),
      "demo",
      "demo@redact.app",
      bcrypt.hashSync("redact-demo-2026", 10),
      new Date().toISOString(),
    );
}

export function createUser(username: string, email: string, password: string): UserRow {
  const database = getDb();
  const row: UserRow = {
    id: randomUUID(),
    username,
    email: email.toLowerCase(),
    password_hash: bcrypt.hashSync(password, 10),
    created_at: new Date().toISOString(),
  };
  database
    .prepare(
      "INSERT INTO users (id, username, email, password_hash, created_at) VALUES (@id, @username, @email, @password_hash, @created_at)",
    )
    .run(row);
  return row;
}

export function findUserByEmail(email: string): UserRow | undefined {
  return getDb()
    .prepare("SELECT * FROM users WHERE email = ?")
    .get(email.toLowerCase()) as UserRow | undefined;
}

export function findUserById(id: string): UserRow | undefined {
  return getDb().prepare("SELECT * FROM users WHERE id = ?").get(id) as UserRow | undefined;
}

export function verifyPassword(user: UserRow, password: string): boolean {
  return bcrypt.compareSync(password, user.password_hash);
}

export function insertAudit(row: AuditRow) {
  getDb()
    .prepare(
      `INSERT INTO audit_logs (
        id, user_id, action, data_hash, method, redaction_level, encryption_used,
        domain, entity_types, previous_hash, chain_hash, created_at
      ) VALUES (
        @id, @user_id, @action, @data_hash, @method, @redaction_level, @encryption_used,
        @domain, @entity_types, @previous_hash, @chain_hash, @created_at
      )`,
    )
    .run(row);
}

export function latestAuditHash(): string {
  const row = getDb()
    .prepare("SELECT chain_hash FROM audit_logs ORDER BY rowid DESC LIMIT 1")
    .get() as { chain_hash: string } | undefined;
  return row?.chain_hash ?? "0".repeat(64);
}

export function listAuditLogs(userId: string, limit = 100): AuditRow[] {
  return getDb()
    .prepare(
      "SELECT * FROM audit_logs WHERE user_id = ? ORDER BY rowid DESC LIMIT ?",
    )
    .all(userId, limit) as AuditRow[];
}

export function listAllAuditLogs(): AuditRow[] {
  return getDb()
    .prepare("SELECT * FROM audit_logs ORDER BY rowid ASC")
    .all() as AuditRow[];
}

export function insertDownload(row: DownloadRow) {
  getDb()
    .prepare(
      "INSERT INTO downloads (id, user_id, filename, mime, content, created_at) VALUES (@id, @user_id, @filename, @mime, @content, @created_at)",
    )
    .run(row);
}

export function listDownloads(userId: string): Omit<DownloadRow, "content">[] {
  return getDb()
    .prepare(
      "SELECT id, user_id, filename, mime, created_at FROM downloads WHERE user_id = ? ORDER BY created_at DESC",
    )
    .all(userId) as Omit<DownloadRow, "content">[];
}

export function getDownload(id: string, userId: string): DownloadRow | undefined {
  return getDb()
    .prepare("SELECT * FROM downloads WHERE id = ? AND user_id = ?")
    .get(id, userId) as DownloadRow | undefined;
}
