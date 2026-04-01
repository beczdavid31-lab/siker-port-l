const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');

const app = express();
// 50MB limit, hogy több tízezer kontakt is elférjen egy mentésben!
app.use(express.json({ limit: '50mb' })); 
app.use(cors());
app.use(express.static(path.join(__dirname))); 

// --- 1. MONGODB ADATBÁZIS CSATLAKOZÁS ---
// Ezt a titkos kulcsot a Render Environment változóiból olvassa ki
const mongoURI = process.env.MONGO_URI;

if (!mongoURI) {
    console.error('❌ KRITIKUS HIBA: Nincs megadva a MONGO_URI a környezeti változókban!');
    process.exit(1);
}

mongoose.connect(mongoURI)
  .then(() => console.log('✅ Sikeres csatlakozás a MongoDB Felhőhöz!'))
  .catch(err => console.error('❌ MongoDB hálózati hiba:', err));

// --- 2. ADATBÁZIS MODELL (Hogyan néz ki egy felhasználó) ---
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    name: { type: String, required: true },
    crm_data: { type: String, default: '[]' },
    is_shared: { type: Boolean, default: false }
});
const User = mongoose.model('User', userSchema);

const JWT_SECRET = process.env.JWT_SECRET || 'szuper_titkos_kulcs_2026';

// --- 3. BIZTONSÁGI ŐR (Middleware) ---
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

// --- 4. VÉGPONTOK (API) ---

// Regisztráció
app.post('/api/register', async (req, res) => {
    try {
        const { username, password, name } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({ username, password: hashedPassword, name });
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
        
        const token = jwt.sign({ id: user._id, username: user.username }, JWT_SECRET);
        res.json({ token, name: user.name });
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

// CRM Adatok Mentése (Ez már a MongoDB-be megy!)
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

// Csapat adatainak lekérése (Azok, akik megosztották)
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

// Kezdőoldal irányítása
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'kapu.html')));

// --- 5. SZERVER INDÍTÁSA ---
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
    console.log(`🚀 Szerver sikeresen elindult a ${PORT}-es porton!`);
});