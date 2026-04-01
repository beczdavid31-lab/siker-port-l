const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');

const app = express();
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

// --- 2. ADATBÁZIS MODELL ---
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    name: { type: String, required: true },
    fbo_id: { type: String },
    sponsor_fbo: { type: String },
    role: { type: String, default: 'user' }, 
    is_approved: { type: Boolean, default: false }, 
    crm_data: { type: String, default: '[]' },
    is_shared: { type: Boolean, default: false }
});
const User = mongoose.model('User', userSchema);

const JWT_SECRET = process.env.JWT_SECRET || 'szuper_titkos_kulcs_2026';

// --- 3. BIZTONSÁGI ŐRÖK ---
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

app.post('/api/register', async (req, res) => {
    try {
        const { username, password, name, fbo_id, sponsor_fbo } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);
        
        const userCount = await User.countDocuments();
        
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
        res.status(201).json({ message: 'Sikeres regisztráció! Fiókod jóváhagyásra vár.' });
    } catch (error) {
        res.status(400).json({ error: 'A felhasználónév már foglalt, vagy hiba történt.' });
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const user = await User.findOne({ username });
        if (!user) return res.status(400).json({ error: 'Nincs ilyen felhasználó.' });
        
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) return res.status(400).json({ error: 'Hibás jelszó.' });
        
        if (!user.is_approved) {
            return res.status(403).json({ error: 'A fiókod még jóváhagyásra vár! Kérlek, jelezd a szponzorodnak vagy egy Adminnak.' });
        }
        
        const token = jwt.sign({ id: user._id, username: user.username }, JWT_SECRET);
        res.json({ token, name: user.name, role: user.role });
    } catch (error) {
        res.status(500).json({ error: 'Szerver hiba.' });
    }
});

app.get('/api/data', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.id);
        res.json({ crm_data: user.crm_data, is_shared: user.is_shared ? 1 : 0 });
    } catch (error) {
        res.status(500).json({ error: 'Hiba az adatok lekérésekor.' });
    }
});

app.post('/api/data', authenticateToken, async (req, res) => {
    try {
        await User.findByIdAndUpdate(req.user.id, { crm_data: req.body.crm_data });
        res.json({ message: 'Mentés sikeres a felhőben!' });
    } catch (error) {
        res.status(500).json({ error: 'Hiba a mentés során.' });
    }
});

app.post('/api/share', authenticateToken, async (req, res) => {
    try {
        await User.findByIdAndUpdate(req.user.id, { is_shared: req.body.is_shared });
        res.json({ message: 'Megosztás állapota frissítve!' });
    } catch (error) {
        res.status(500).json({ error: 'Hiba a megosztásnál.' });
    }
});

app.get('/api/team/shared', authenticateToken, async (req, res) => {
    try {
        const users = await User.find({ is_shared: true, _id: { $ne: req.user.id } }, '_id name');
        const formattedUsers = users.map(u => ({ id: u._id, name: u.name }));
        res.json(formattedUsers);
    } catch (error) {
        res.status(500).json({ error: 'Hiba a csapat lekérésekor.' });
    }
});

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

// --- 5. ADMIN VÉGPONTOK ---
app.get('/api/admin/users', authenticateAdmin, async (req, res) => {
    try {
        const users = await User.find({}, '-password'); 
        res.json(users);
    } catch (error) {
        res.status(500).json({ error: 'Hiba a felhasználók lekérésekor.' });
    }
});

app.post('/api/admin/approve/:id', authenticateAdmin, async (req, res) => {
    try {
        await User.findByIdAndUpdate(req.params.id, { is_approved: true });
        res.json({ message: 'Felhasználó sikeresen jóváhagyva!' });
    } catch (error) {
        res.status(500).json({ error: 'Hiba a jóváhagyás során.' });
    }
});

app.post('/api/admin/make-admin/:id', authenticateAdmin, async (req, res) => {
    try {
        await User.findByIdAndUpdate(req.params.id, { role: 'admin', is_approved: true });
        res.json({ message: 'A felhasználó mostantól Admin!' });
    } catch (error) {
        res.status(500).json({ error: 'Hiba a jogosultság adásakor.' });
    }
});

app.delete('/api/admin/user/:id', authenticateAdmin, async (req, res) => {
    try {
        await User.findByIdAndDelete(req.params.id);
        res.json({ message: 'Felhasználó sikeresen törölve!' });
    } catch (error) {
        res.status(500).json({ error: 'Hiba a törlés során.' });
    }
});

// --- 6. AI ASSZISZTENS VÉGPONT (GEMINI INTEGRÁCIÓ) 🤖 ---
app.post('/api/ai-parse', authenticateToken, async (req, res) => {
    try {
        const { rawText } = req.body;
        const apiKey = process.env.GEMINI_API_KEY;

        if (!apiKey) {
            return res.status(500).json({ error: 'Nincs beállítva a Gemini API kulcs a szerveren!' });
        }

        const prompt = `Légy szíves nyerd ki a következő magyar nyelvű szövegből a CRM adatokat, és KIZÁRÓLAG egy érvényes JSON objektumot adj vissza (ne használj markdown formázást, se \`\`\`json jelölést, csak a tiszta JSON-t), a következő kulcsokkal: "name" (név), "email" (email cím), "phone" (telefonszám), "notes" (minden egyéb hasznos megjegyzés). Ha valamelyik adat hiányzik a szövegből, hagyd az értékét üresen (""). Szöveg: "${rawText}"`;

        // A GOLYÓÁLLÓ, KLASSZIKUS MODELL: gemini-pro
        const response = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent?key=${apiKey}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                contents: [{ parts: [{ text: prompt }] }]
            })
        });

        const data = await response.json();
        
        if (data.error) {
            throw new Error(data.error.message);
        }

        const aiText = data.candidates[0].content.parts[0].text;
        
        const cleanJsonStr = aiText.replace(/```json/gi, '').replace(/```/g, '').trim();
        const parsedData = JSON.parse(cleanJsonStr);

        res.json(parsedData); 
    } catch (error) {
        console.error('AI Hiba:', error);
        res.status(500).json({ error: 'Hiba történt a mesterséges intelligencia feldolgozása során.' });
    }
});

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'kapu.html')));

// --- 7. SZERVER INDÍTÁSA ---
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
    console.log(`🚀 Szerver sikeresen elindult a ${PORT}-es porton!`);
});