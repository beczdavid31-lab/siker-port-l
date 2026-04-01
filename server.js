const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');

const app = express();
// 50MB limit, hogy több tízezer kontakt is elférjen egy mentésben
app.use(express.json({ limit: '50mb' })); 
app.use(cors());
app.use(express.static(path.join(__dirname))); 

// --- 1. MONGODB ADATBÁZIS CSATLAKOZÁS ---
const mongoURI = process.env.MONGO_URI;

if (!mongoURI) {
    console.error('❌ KRITIKUS HIBA: Nincs megadva a MONGO_URI a környezeti változókban!');
    process.exit(1);
}

mongoose.connect(mongoURI)
  .then(() => console.log('✅ Sikeres csatlakozás a MongoDB Felhőhöz!'))
  .catch(err => console.error('❌ MongoDB hálózati hiba:', err));

// --- 2. ADATBÁZIS MODELL (A felhasználók felépítése) ---
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true }, // E-mail cím
    password: { type: String, required: true },
    name: { type: String, required: true },
    fbo_id: { type: String },
    sponsor_fbo: { type: String },
    role: { type: String, default: 'user' }, // 'admin' vagy 'user'
    is_approved: { type: Boolean, default: false }, // Jóváhagyta-e már egy Admin
    crm_data: { type: String, default: '[]' },
    is_shared: { type: Boolean, default: false }
});
const User = mongoose.model('User', userSchema);

const JWT_SECRET = process.env.JWT_SECRET || 'szuper_titkos_kulcs_2026';

// --- 3. BIZTONSÁGI ŐRÖK (Middleware) ---

// Sima bejelentkezés ellenőrzése
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.sendStatus(401);
    
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

// Külön Szigorú Admin ellenőrzés
const authenticateAdmin = async (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.sendStatus(401);
    
    jwt.verify(token, JWT_SECRET, async (err, decodedToken) => {
        if (err) return res.sendStatus(403);
        
        const user = await User.findById(decodedToken.id);
        if (!user || user.role !== 'admin') {
            return res.status(403).json({ error: 'Nincs admin jogosultságod!' });
        }
        
        req.user = user;
        next();
    });
};

// --- 4. ALAP VÉGPONTOK (API) ---

// Regisztráció (Az első ember automatikusan Admin lesz)
app.post('/api/register', async (req, res) => {
    try {
        const { username, password, name, fbo_id, sponsor_fbo } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);
        
        // Megnézzük, hányan vannak már a rendszerben
        const userCount = await User.countDocuments();
        
        // Ha 0 ember van, akkor ez a legelső regisztráció -> Ő lesz az ADMIN!
        // Az Admin fiók alapból jóvá is van hagyva (is_approved: true)
        const userRole = (userCount === 0) ? 'admin' : 'user';
        const isApproved = (userCount === 0) ? true : false;

        const user = new User({ 
            username, 
            password: hashedPassword, 
            name, 
            fbo_id,
            sponsor_fbo,
            role: userRole,
            is_approved: isApproved
        });
        
        await user.save();
        res.status(201).json({ message: 'Sikeres regisztráció!' });
    } catch (error) {
        console.error(error);
        res.status(400).json({ error: 'A felhasználónév már foglalt, vagy hiba történt.' });
    }
});

// Bejelentkezés
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const user = await User.findOne({ username });
        if (!user) return res.status(400).json({ error: 'Nincs ilyen felhasználó.' });
        
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) return res.status(400).json({ error: 'Hibás jelszó.' });
        
        // (Opcionális: Később ide betehetjük, hogy ha user.is_approved === false, ne engedje be a CRM-be, 
        // de egyelőre beengedjük a Központba)
        
        const token = jwt.sign({ id: user._id, username: user.username }, JWT_SECRET);
        
        // Visszaküldjük a rangot (role) is!
        res.json({ token, name: user.name, role: user.role });
    } catch (error) {
        res.status(500).json({ error: 'Szerver hiba.' });
    }
});

// CRM Adatok Lekérése
app.get('/api/data', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.id);
        res.json({ crm_data: user.crm_data, is_shared: user.is_shared ? 1 : 0 });
    } catch (error) {
        res.status(500).json({ error: 'Hiba az adatok lekérésekor.' });
    }
});

// CRM Adatok Mentése
app.post('/api/data', authenticateToken, async (req, res) => {
    try {
        await User.findByIdAndUpdate(req.user.id, { crm_data: req.body.crm_data });
        res.json({ message: 'Mentés sikeres a felhőben!' });
    } catch (error) {
        res.status(500).json({ error: 'Hiba a mentés során.' });
    }
});

// Megosztás beállítása
app.post('/api/share', authenticateToken, async (req, res) => {
    try {
        await User.findByIdAndUpdate(req.user.id, { is_shared: req.body.is_shared });
        res.json({ message: 'Megosztás állapota frissítve!' });
    } catch (error) {
        res.status(500).json({ error: 'Hiba a megosztásnál.' });
    }
});

// Csapat adatainak lekérése
app.get('/api/team/shared', authenticateToken, async (req, res) => {
    try {
        const users = await User.find({ is_shared: true, _id: { $ne: req.user.id } }, '_id name');
        const formattedUsers = users.map(u => ({ id: u._id, name: u.name }));
        res.json(formattedUsers);
    } catch (error) {
        res.status(500).json({ error: 'Hiba a csapat lekérésekor.' });
    }
});

// Egy adott csapattag névlistájának lekérése
app.get('/api/team/shared/:id', authenticateToken, async (req, res) => {
    try {
        const targetUser = await User.findById(req.params.id);
        if (!targetUser || !targetUser.is_shared) {
            return res.status(403).json({ error: 'Nincs jogosultságod ehhez a listához.' });
        }
        res.json({ name: targetUser.name, crm_data: targetUser.crm_data });
    } catch (error) {
        res.status(500).json({ error: 'Hiba a csapattag lekérésekor.' });
    }
});

// --- 5. ADMIN VÉGPONTOK (Csak a Király férhet hozzá) ---

// Összes felhasználó lekérése az Admin Panelhez
app.get('/api/admin/users', authenticateAdmin, async (req, res) => {
    try {
        const users = await User.find({}, '-password'); // Jelszó nélkül küldjük!
        res.json(users);
    } catch (error) {
        res.status(500).json({ error: 'Hiba a felhasználók lekérésekor.' });
    }
});

// Felhasználó jóváhagyása
app.post('/api/admin/approve/:id', authenticateAdmin, async (req, res) => {
    try {
        await User.findByIdAndUpdate(req.params.id, { is_approved: true });
        res.json({ message: 'Felhasználó sikeresen jóváhagyva!' });
    } catch (error) {
        res.status(500).json({ error: 'Hiba a jóváhagyás során.' });
    }
});

// Felhasználó Adminná tétele
app.post('/api/admin/make-admin/:id', authenticateAdmin, async (req, res) => {
    try {
        await User.findByIdAndUpdate(req.params.id, { role: 'admin', is_approved: true });
        res.json({ message: 'A felhasználó mostantól Admin!' });
    } catch (error) {
        res.status(500).json({ error: 'Hiba a jogosultság adásakor.' });
    }
});

// Felhasználó végleges törlése
app.delete('/api/admin/user/:id', authenticateAdmin, async (req, res) => {
    try {
        await User.findByIdAndDelete(req.params.id);
        res.json({ message: 'Felhasználó sikeresen törölve!' });
    } catch (error) {
        res.status(500).json({ error: 'Hiba a törlés során.' });
    }
});

// Kezdőoldal irányítása
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'kapu.html')));

// --- 6. SZERVER INDÍTÁSA ---
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
    console.log(`🚀 Szerver sikeresen elindult a ${PORT}-es porton!`);
});