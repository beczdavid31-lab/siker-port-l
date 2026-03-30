const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
const port = process.env.PORT || 3000;
const SECRET_KEY = 'SikerPortalTitkosKulcs2026'; 

app.use(express.json({ limit: '50mb' })); 
app.use(cors());
app.use(express.static(__dirname)); 

// --- 1. ADATBÁZIS KAPCSOLAT ---
const db = new sqlite3.Database(path.join(__dirname, 'siker_portal.db'));

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    email TEXT UNIQUE,
    password TEXT,
    fbo_id TEXT,
    sponsor_fbo TEXT, 
    role TEXT DEFAULT 'user',
    is_approved INTEGER DEFAULT 0,
    crm_data TEXT DEFAULT '[]',
    is_shared INTEGER DEFAULT 0 
  )`);
});

// --- 2. BIZTONSÁGI ELLENŐRZŐK ---
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.sendStatus(401);

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user; 
    next();
  });
}

function requireAdmin(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Nincs admin jogosultságod!' });
  next();
}

// --- 3. REGISZTRÁCIÓ ÉS BELÉPÉS ---
app.post('/register', async (req, res) => {
  const { name, email, password, fbo_id, sponsor_fbo } = req.body;
  if (!fbo_id || fbo_id.length !== 12 || isNaN(fbo_id)) return res.status(400).json({ error: 'A te kódod hibás!' });
  
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    db.get(`SELECT COUNT(*) as count FROM users`, [], (err, row) => {
      let role = 'user', is_approved = 0;
      if (row.count === 0) { role = 'admin'; is_approved = 1; }

      db.run(`INSERT INTO users (name, email, password, fbo_id, sponsor_fbo, role, is_approved) VALUES (?, ?, ?, ?, ?, ?, ?)`, 
        [name, email, hashedPassword, fbo_id, sponsor_fbo || '', role, is_approved], function(err) {
          if (err) return res.status(400).json({ error: 'Ez az e-mail már létezik!' });
          res.json({ message: role === 'admin' ? 'Te vagy az Admin, azonnal beléphetsz!' : 'Sikeres regisztráció! Várj a jóváhagyásra.' });
      });
    });
  } catch (error) { res.status(500).json({ error: 'Hiba történt.' }); }
});

app.post('/login', (req, res) => {
  const { email, password } = req.body;
  db.get(`SELECT * FROM users WHERE email = ?`, [email], async (err, user) => {
    if (err || !user) return res.status(400).json({ error: 'Hibás e-mail vagy jelszó!' });
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ error: 'Hibás e-mail vagy jelszó!' });
    if (user.is_approved === 0) return res.status(403).json({ error: 'Nincs jóváhagyva a fiókod!' });

    const token = jwt.sign({ id: user.id, role: user.role }, SECRET_KEY, { expiresIn: '24h' });
    res.json({ message: 'Sikeres belépés!', token: token, name: user.name, role: user.role });
  });
});

// --- CRM ÉS CSAPAT VÉGPONTOK ---
app.get('/api/data', authenticateToken, (req, res) => {
  db.get(`SELECT crm_data, is_shared FROM users WHERE id = ?`, [req.user.id], (err, row) => {
    res.json({ crm_data: row ? row.crm_data : '[]', is_shared: row ? row.is_shared : 0 });
  });
});
app.post('/api/data', authenticateToken, (req, res) => {
  db.run(`UPDATE users SET crm_data = ? WHERE id = ?`, [req.body.crm_data, req.user.id], () => res.json({ success: true }));
});
app.post('/api/share', authenticateToken, (req, res) => {
  db.run(`UPDATE users SET is_shared = ? WHERE id = ?`, [req.body.is_shared ? 1 : 0, req.user.id], () => res.json({ success: true }));
});
app.get('/api/team/shared', authenticateToken, (req, res) => {
  db.get(`SELECT fbo_id FROM users WHERE id = ?`, [req.user.id], (err, me) => {
    db.all(`SELECT id, name FROM users WHERE sponsor_fbo = ? AND is_shared = 1`, [me.fbo_id], (err, rows) => res.json(rows || []));
  });
});
app.get('/api/team/shared/:id', authenticateToken, (req, res) => {
  db.get(`SELECT fbo_id FROM users WHERE id = ?`, [req.user.id], (err, me) => {
    db.get(`SELECT name, crm_data FROM users WHERE id = ? AND sponsor_fbo = ? AND is_shared = 1`, [req.params.id, me.fbo_id], (err, row) => {
      res.json(row ? { name: row.name, crm_data: row.crm_data } : { error: 'Nincs jogosultság' });
    });
  });
});

// --- ADMIN VÉGPONTOK ---
app.get('/api/admin/users', authenticateToken, requireAdmin, (req, res) => {
  db.all(`SELECT * FROM users ORDER BY id DESC`, [], (err, rows) => res.json(rows));
});
app.post('/api/admin/approve/:id', authenticateToken, requireAdmin, (req, res) => {
  db.run(`UPDATE users SET is_approved = 1 WHERE id = ?`, [req.params.id], () => res.json({ success: true }));
});
app.post('/api/admin/make-admin/:id', authenticateToken, requireAdmin, (req, res) => {
  db.run(`UPDATE users SET role = 'admin', is_approved = 1 WHERE id = ?`, [req.params.id], () => res.json({ success: true }));
});
app.delete('/api/admin/user/:id', authenticateToken, requireAdmin, (req, res) => {
  db.run(`DELETE FROM users WHERE id = ? AND role != 'admin'`, [req.params.id], () => res.json({ success: true }));
});

app.listen(port, () => { console.log(`🚀 Szerver fut a ${port}-es porton...`); });