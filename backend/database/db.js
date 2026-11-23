
"use strict";

const path = require("path");
const fs = require("fs");
const Database = require("better-sqlite3");

// Ajiye database a cikin backend/data
const dataDirectory = path.join(__dirname, "..", "data");

if (!fs.existsSync(dataDirectory)) {
  fs.mkdirSync(dataDirectory, { recursive: true });
}

const databasePath = path.join(dataDirectory, "wallet.db");
const db = new Database(databasePath);

// Kariya da ingantaccen aiki
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

// Teburin masu amfani da tsarin
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    full_name TEXT NOT NULL,
    role TEXT NOT NULL CHECK (
      role IN ('Super Admin', 'Finance Officer', 'Approver', 'Agent')
    ),
    agent_id TEXT UNIQUE,
    is_active INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1)),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS agents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_code TEXT NOT NULL UNIQUE,
    full_name TEXT NOT NULL,
    phone TEXT,
    location TEXT,
    status TEXT NOT NULL DEFAULT 'Active'
      CHECK (status IN ('Active', 'Inactive')),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    reference TEXT NOT NULL UNIQUE,
    agent_id INTEGER NOT NULL,
    transaction_type TEXT NOT NULL CHECK (
      transaction_type IN ('Deposit', 'Withdrawal', 'Transfer', 'Adjustment')
    ),
    amount REAL NOT NULL CHECK (amount > 0),
    reason TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'Pending' CHECK (
      status IN ('Pending', 'Approved', 'Rejected', 'Completed')
    ),
    requested_by INTEGER,
    reviewed_by INTEGER,
    reviewed_at TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (agent_id) REFERENCES agents(id),
    FOREIGN KEY (requested_by) REFERENCES users(id),
    FOREIGN KEY (reviewed_by) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS wallet_balances (
    agent_id INTEGER PRIMARY KEY,
    balance REAL NOT NULL DEFAULT 0 CHECK (balance >= 0),
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (agent_id) REFERENCES agents(id)
  );

  CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    action TEXT NOT NULL,
    details TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
  );
`);

console.log("Wallet database an shirya:", databasePath);

module.exports = db;
