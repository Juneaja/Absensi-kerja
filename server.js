
const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const db = require('./database');

const app = express();
app.use(bodyParser.json());
app.use(express.static('public'));

const SECRET_KEY = 'your-secret-key'; // Ganti dengan key aman di produksi

function authenticateToken(req, res, next) {
  const token = req.headers['authorization'];
  if (!token) return res.sendStatus(401);
  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

app.post('/register', (req, res) => {
  const { username, password, name } = req.body;
  const hashedPassword = bcrypt.hashSync(password, 10);
  db.run('INSERT INTO users (username, password, role, name) VALUES (?, ?, ?, ?)',
    [username, hashedPassword, 'employee', name], function(err) {
      if (err) return res.status(400).json({ message: 'Username sudah ada' });
      res.json({ message: 'Registrasi berhasil' });
    });
});

app.post('/login', (req, res) => {
  const { username, password, role } = req.body;
  db.get('SELECT * FROM users WHERE username = ? AND role = ?', [username, role], (err, user) => {
    if (err) return res.status(500).json({ message: 'Error database' });
    if (user && bcrypt.compareSync(password, user.password)) {
      const token = jwt.sign({ id: user.id, role: user.role }, SECRET_KEY);
      res.json({ token });
    } else {
      res.status(401).json({ message: 'Kredensial salah' });
    }
  });
});

app.post('/check-in', authenticateToken, (req, res) => {
  if (req.user.role !== 'employee') return res.sendStatus(403);
  const now = new Date();
  const date = now.toISOString().split('T')[0];
  db.get('SELECT * FROM schedules WHERE userId = ? AND date = ?', [req.user.id, date], (err, row) => {
    if (err) return res.status(500).json({ message: 'Error database' });
    if (row && row.checkIn) return res.status(400).json({ message: 'Sudah check-in hari ini' });
    if (row) {
      db.run('UPDATE schedules SET checkIn = ? WHERE id = ?', [now.toISOString(), row.id], (err) => {
        if (err) return res.status(500).json({ message: 'Error database' });
        res.json({ message: 'Check-in berhasil' });
      });
    } else {
      db.run('INSERT INTO schedules (userId, checkIn, date) VALUES (?, ?, ?)',
        [req.user.id, now.toISOString(), date], function(err) {
          if (err) return res.status(500).json({ message: 'Error database' });
          res.json({ message: 'Check-in berhasil' });
        });
    }
  });
});

app.post('/check-out', authenticateToken, (req, res) => {
  if (req.user.role !== 'employee') return res.sendStatus(403);
  const now = new Date();
  const date = now.toISOString().split('T')[0];
  db.get('SELECT * FROM schedules WHERE userId = ? AND date = ?', [req.user.id, date], (err, row) => {
    if (err) return res.status(500).json({ message: 'Error database' });
    if (!row || !row.checkIn) return res.status(400).json({ message: 'Belum check-in hari ini' });
    if (row.checkOut) return res.status(400).json({ message: 'Sudah check-out hari ini' });
    db.run('UPDATE schedules SET checkOut = ? WHERE id = ?', [now.toISOString(), row.id], (err) => {
      if (err) return res.status(500).json({ message: 'Error database' });
      res.json({ message: 'Check-out berhasil' });
    });
  });
});

app.get('/my-schedule', authenticateToken, (req, res) => {
  if (req.user.role !== 'employee') return res.sendStatus(403);
  db.all('SELECT * FROM schedules WHERE userId = ? ORDER BY date DESC', [req.user.id], (err, rows) => {
    if (err) return res.status(500).json({ message: 'Error database' });
    res.json({ schedules: rows });
  });
});

app.get('/reports', authenticateToken, (req, res) => {
  if (req.user.role !== 'admin') return res.sendStatus(403);
  db.all('SELECT u.name, s.* FROM schedules s JOIN users u ON s.userId = u.id ORDER BY s.date DESC', [], (err, rows) => {
    if (err) return res.status(500).json({ message: 'Error database' });
    res.json({ reports: rows });
  });
});

app.listen(3000, () => console.log('Server berjalan di port 3000'));
