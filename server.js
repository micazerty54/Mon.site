require('dotenv').config();
const express = require('express');
const fs = require('fs');
const path = require('path');
const http = require('http');
const WebSocket = require('ws');
const multer = require('multer');
const session = require('express-session');
const ffmpeg = require('fluent-ffmpeg');

// --- CONFIGURATION FFmpeg ---
ffmpeg.setFfmpegPath(process.env.FFMPEG_PATH);
const app = express();
const server = http.createServer(app);

// Augmenter les limites pour les gros fichiers (2.5 Go)
app.use(express.json({ limit: '2500mb' }));
app.use(express.urlencoded({ limit: '2500mb', extended: true }));

// Timeout long pour laisser le temps aux gros uploads
server.timeout = 900000; 

const wss = new WebSocket.Server({ server });

// --- CHEMINS ET CONSTANTES ---
const FILES_DIR = path.join(__dirname, 'public', 'files');
const MSG_FILE = path.join(__dirname, 'messages.json');
const STATIC_DIR = path.join(__dirname, 'public');

const VALID_CODE = process.env.VALID_CODE;
const ADMIN_CODE = process.env.ADMIN_CODE;

// --- MIDDLEWARE SESSION ---
app.use(session({
    name: process.env.SESSION_COOKIE_NAME || 'mon_cookie_session',
    secret: process.env.SESSION_SECRET || 'secret_par_defaut',
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        sameSite: "lax",
        maxAge: 60 * 60 * 1000
    }
}));


// Création dossiers/fichiers si inexistants
if (!fs.existsSync(FILES_DIR)) fs.mkdirSync(FILES_DIR, { recursive: true });
if (!fs.existsSync(MSG_FILE)) fs.writeFileSync(MSG_FILE, '[]', 'utf8');

// Route pour la page de connexion (index.html) avec titre dynamique
app.get('/', (req, res) => {
    const filePath = path.join(STATIC_DIR, 'index.html');
    if (!fs.existsSync(filePath)) return res.status(404).send('index.html non trouvé');

    let html = fs.readFileSync(filePath, 'utf8');

    // On utilise LOG_TITLE défini dans le .env
    const logTitle = process.env.LOG_TITLE || 'Connexion';
    html = html.replace(/<title>.*<\/title>/, `<title>${logTitle}</title>`);

    res.send(html);
});

// --- PROTECTION & SERVEUR STATIQUE ---
// 1. Protection spécifique de onglets.html
app.use((req, res, next) => {
    if (req.path === "/onglets.html") {
        if (req.session && req.session.authenticated) return next();
        else return res.redirect("/");
    }
    next();
});

// 2. Serveur statique sauf le dossier /files/ (géré manuellement plus bas pour la sécurité)
app.use((req, res, next) => {
    if (!req.path.startsWith("/files/")) {
        express.static(STATIC_DIR)(req, res, next);
    } else {
        next();
    }
});
app.get('/onglets.html', (req, res) => {
    if (!req.session || !req.session.authenticated) return res.redirect('/');

    const filePath = path.join(STATIC_DIR, 'onglets.html');
    let html = fs.readFileSync(filePath, 'utf8');

    // Remplacement du titre par SITE_TITLE
    const siteTitle = process.env.SITE_TITLE || 'Mon site';
    html = html.replace(/<title>.*<\/title>/, `<title>${siteTitle}</title>`);

    res.send(html);
});
app.get('/api/site-title', (req, res) => {
    res.json({ title: process.env.SITE_TITLE || 'Mimi mon site' });
});
app.get('/api/iframe-links', (req, res) => {
    res.json({
        site2: process.env.IFRAME_SITE_2 || '',
        site3: process.env.IFRAME_SITE_3 || ''
    });
});
// --- RATE LIMITING ---
const loginAttemptsSite = {};
const loginAttemptsAdmin = {};

function checkRateLimit(attemptsObj, key, maxAttempts, windowMs) {
    const now = Date.now();
    if (!attemptsObj[key]) attemptsObj[key] = [];
    attemptsObj[key] = attemptsObj[key].filter(t => now - t < windowMs);
    return attemptsObj[key].length < maxAttempts;
}

function addAttempt(attemptsObj, key) {
    if (!attemptsObj[key]) attemptsObj[key] = [];
    attemptsObj[key].push(Date.now());
}

// --- AUTHENTIFICATION ---
app.post('/check-password', (req, res) => {
    const { code } = req.body;
    const ip = req.ip;
    if (!checkRateLimit(loginAttemptsSite, ip, 100, 600000)) return res.status(429).json({ ok: false, error: 'Trop de tentatives' });

    if (code === VALID_CODE) {
        req.session.authenticated = true;
        loginAttemptsSite[ip] = [];
        return res.json({ ok: true });
    }
    addAttempt(loginAttemptsSite, ip);
    res.json({ ok: false });
});

app.post('/api/admin/login', (req, res) => {
    const { code } = req.body;
    const ip = req.ip;
    if (!checkRateLimit(loginAttemptsAdmin, ip, 5, 600000)) return res.status(429).json({ success: false, error: 'Trop de tentatives' });

    if (code === ADMIN_CODE) {
        req.session.isAdmin = true;
        loginAttemptsAdmin[ip] = [];
        return res.json({ success: true });
    }
    addAttempt(loginAttemptsAdmin, ip);
    res.status(403).json({ success: false });
});

// --- GESTION UPLOADS ---
const ALLOWED_UPLOAD_EXTENSIONS = ['.avi', '.wma', '.png', '.jpg', '.jpeg', '.gif', '.webp', '.mp4', '.webm', '.mov', '.mp3', '.wav', '.ogg', '.pdf', '.txt', '.doc', '.docx', '.zip'];

const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, FILES_DIR),
    filename: (req, file, cb) => {
        const parsed = path.parse(file.originalname);
        const safeBase = parsed.name.replace(/[^a-zA-Z0-9-_]/g, '_');
        const ext = parsed.ext.toLowerCase();
        const now = new Date();
        const formattedDate = new Intl.DateTimeFormat('fr-FR', {
            timeZone: 'Europe/Paris',
            year: 'numeric', month: '2-digit', day: '2-digit',
            hour: '2-digit', minute: '2-digit', second: '2-digit'
        }).format(now).replace(/ /g, '_').replace(/\//g, '-').replace(/:/g, '-');

        cb(null, `${safeBase}-${formattedDate}${ext}`);
    }
});

const upload = multer({ 
    storage, 
    fileFilter: (req, file, cb) => {
        const ext = path.extname(file.originalname).toLowerCase();
        if (ALLOWED_UPLOAD_EXTENSIONS.includes(ext)) cb(null, true);
        else cb(new Error('Type non autorisé'), false);
    } 
});

async function processMedia(file) {
    const tempPath = file.path;
    const originalExt = path.extname(file.originalname).toLowerCase();
    const safeBase = path.parse(file.originalname).name.replace(/[^a-zA-Z0-9-_]/g, '_');
    
    const now = new Date();
    const formattedDate = new Intl.DateTimeFormat('fr-FR', {
        timeZone: 'Europe/Paris',
        year: 'numeric', month: '2-digit', day: '2-digit',
        hour: '2-digit', minute: '2-digit', second: '2-digit'
    }).format(now).replace(/ /g, '_').replace(/\//g, '-').replace(/:/g, '-');

    const finalNameBase = `${safeBase}-${formattedDate}`;
    
    let targetExt = '';
    if (file.mimetype.startsWith('video/') && originalExt !== '.mp4') targetExt = '.mp4';
    else if (file.mimetype.startsWith('audio/') && originalExt !== '.mp3') targetExt = '.mp3';

    // Si déjà au bon format ou pas de conversion prévue
    if (!targetExt || targetExt === originalExt) {
        const finalName = finalNameBase + originalExt;
        const finalPath = path.join(FILES_DIR, finalName);
        fs.renameSync(tempPath, finalPath);
        return finalName;
    }

    // Conversion avec FFmpeg
    const convName = finalNameBase + targetExt;
    const convPath = path.join(FILES_DIR, convName);

    return new Promise((resolve) => {
        ffmpeg(tempPath)
            .toFormat(targetExt.replace('.', ''))
            .on('end', () => {
                if (fs.existsSync(tempPath)) fs.unlinkSync(tempPath);
                resolve(convName);
            })
            .on('error', (err) => {
                console.error("Erreur FFmpeg:", err);
                const fallback = finalNameBase + originalExt;
                fs.renameSync(tempPath, path.join(FILES_DIR, fallback));
                resolve(fallback);
            })
            .save(convPath);
    });
}

app.post('/api/upload', (req, res, next) => {
    if (!req.session || !req.session.authenticated) return res.status(403).json({ success: false });
    next();
}, upload.array('file'), async (req, res) => {
    if (!req.files || req.files.length === 0) return res.json({ success: false });
    try {
        const processed = [];
        for (const f of req.files) {
            processed.push(await processMedia(f));
        }
        res.json({ success: true, files: processed });
    } catch (err) {
        res.status(500).json({ success: false });
    }
});

// --- GESTION DES FICHIERS ---
app.get('/api/files', (req, res) => {
    const { type, start = 0, count = 10, q = '' } = req.query;
    fs.readdir(FILES_DIR, (err, files) => {
        if (err) return res.json({ files: [] });
        
        let fileList = files.map(f => {
            try { return { name: f, time: fs.statSync(path.join(FILES_DIR, f)).mtime }; }
            catch(e) { return null; }
        }).filter(f => f !== null);

        fileList.sort((a, b) => b.time - a.time);

        const extMap = {
            photos: ['.png', '.jpg', '.jpeg', '.gif', '.webp'],
            videos: ['.mp4', '.webm', '.mov'],
            sons: ['.mp3', '.wav', '.ogg'],
            docs: ['.pdf', '.txt', '.doc', '.docx']
        };

        let filtered = fileList.filter(f => {
            const ext = path.extname(f.name).toLowerCase();
            const nameMatch = f.name.toLowerCase().includes(q.toLowerCase());
            if (!nameMatch) return false;
            if (extMap[type]) return extMap[type].includes(ext);
            if (type === 'autres') return !Object.values(extMap).flat().includes(ext);
            return true;
        }).map(f => f.name);

        res.json({ files: filtered.slice(Number(start), Number(start) + Number(count)) });
    });
});

app.delete('/api/files/:filename', (req, res) => {
    if (!req.session || !req.session.isAdmin) return res.status(403).json({ success: false });
    const filename = path.basename(req.params.filename);
    const filePath = path.join(FILES_DIR, filename);
    fs.unlink(filePath, err => res.json({ success: !err }));
});

// Sécurisation de l'accès direct aux fichiers
app.get('/files/:filename', (req, res) => {
    if (!req.session || !req.session.authenticated) return res.status(403).send('Accès refusé');
    const filename = path.basename(req.params.filename);
    const filePath = path.join(FILES_DIR, filename);
    if (!fs.existsSync(filePath)) return res.status(404).send('Non trouvé');
    res.sendFile(filePath);
});

// --- CHAT & WEBSOCKET ---
function broadcast(msg) {
    wss.clients.forEach(client => {
        if (client.readyState === WebSocket.OPEN) client.send(JSON.stringify(msg));
    });
}

wss.on('connection', ws => {
    let history = [];
    try { history = JSON.parse(fs.readFileSync(MSG_FILE, 'utf8')); } catch (e) {}
    ws.send(JSON.stringify({ type: 'history', data: history }));

    ws.on('message', message => {
        try {
            let msg = JSON.parse(message);
            if (msg.type === 'message') {
                msg.time = Date.now();
                let messages = JSON.parse(fs.readFileSync(MSG_FILE, 'utf8') || '[]');
                messages.push(msg);
                fs.writeFileSync(MSG_FILE, JSON.stringify(messages, null, 2));
                broadcast(msg);
            }
        } catch (e) {}
    });
});

app.get('/messages.json', (req, res) => {
    if (req.session && req.session.authenticated) {
        res.setHeader('Cache-Control', 'no-store');
        res.sendFile(MSG_FILE);
    } else {
        res.status(403).send('Interdit');
    }
});

app.delete('/api/messages', (req, res) => {
    if (!req.session || !req.session.isAdmin) return res.status(403).json({ success: false });
    fs.writeFileSync(MSG_FILE, '[]');
    broadcast({ type: 'history', data: [] });
    res.json({ success: true });
});

app.post('/api/admin/logout', (req, res) => {
    if (req.session) {
        req.session.destroy(() => {
            res.clearCookie(process.env.SESSION_COOKIE_NAME || 'mon_cookie_session');
            res.json({ success: true });
        });
    } else {
        res.json({ success: true });
    }
});


const PORT = process.env.PORT;
server.listen(PORT, "0.0.0.0", () => {
    console.log(`🚀 Serveur actif sur le port ${PORT}`);
});