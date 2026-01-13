const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('./jadwal_kerja.db');

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT,
    role TEXT,
    name TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS schedules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    userId INTEGER,
    checkIn TEXT,
    checkOut TEXT,
    date TEXT,
    status TEXT DEFAULT 'present',
    FOREIGN KEY (userId) REFERENCES users(id)
  )`);

  // Data awal admin (password: admin123)
  const bcrypt = require('bcryptjs');
  const hashedAdminPass = bcrypt.hashSync('admin123', 10);
  db.run(`INSERT OR IGNORE INTO users (username, password, role, name) VALUES (?, ?, ?, ?)`,
    ['admin', hashedAdminPass, 'admin', 'Administrator']);
});

module.exports = db;
