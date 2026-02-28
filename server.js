const express = require('express');
const session = require('express-session');
const http = require('http');
const socketIo = require('socket.io');
const path = require('path');
const multer = require('multer');
const fs = require('fs');
const pdfParse = require('pdf-parse');

const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });
const upload = multer({
    dest: uploadDir,
    limits: { fileSize: 25 * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
        if (file.mimetype === 'application/pdf') cb(null, true);
        else cb(new Error('Only PDF allowed'), false);
    }
});

const app = express();
const server = http.createServer(app);
const io = socketIo(server, { maxHttpBufferSize: 50 * 1024 * 1024 }); // 50MB for audio uploads

// Middleware
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));
app.use(express.static('public'));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Session configuration
app.use(session({
    secret: process.env.SESSION_SECRET || 'homework-helper-secret-key-2025',
    resave: false,
    saveUninitialized: false,
    cookie: {
        maxAge: 24 * 60 * 60 * 1000 // 24 hours
    }
}));

// Validate required environment variables
const requiredEnvVars = ['APP_PASSWORD', 'REZ67_PASSWORD', 'SHMECKLES67_PASSWORD'];
const missingEnvVars = requiredEnvVars.filter(v => !process.env[v]);
if (missingEnvVars.length > 0) {
    console.error('⚠️  Missing required environment variables:', missingEnvVars.join(', '));
    console.error('   Set them before starting the server or logins will fail.');
}

// In-memory storage
const users = {
    'REZ67': { password: process.env.REZ67_PASSWORD, isAdmin: true, isSuperAdmin: true },
    'shmeckles67': { password: process.env.SHMECKLES67_PASSWORD, isAdmin: true, isSuperAdmin: true }
};
const bannedUsers = [];
const userSettings = {};
const messages = [];
const privateMessages = [];
const onlineUsers = new Map();
const tasks = {};
const userSongs = {};
const musicAlbums = [];
const scanRequests = [];
let ownerBroadcast = { text: '', updatedAt: null };

// Theme name → CSS gradient (must match settings page theme cards)
const THEME_GRADIENTS = {
    pastel: 'linear-gradient(135deg, #a8edea 0%, #fed6e3 100%)',
    purple: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
    sunset: 'linear-gradient(135deg, #f093fb 0%, #f5576c 100%)',
    ocean: 'linear-gradient(135deg, #4facfe 0%, #00f2fe 100%)',
    mint: 'linear-gradient(135deg, #43e97b 0%, #38f9d7 100%)',
    warm: 'linear-gradient(135deg, #fa709a 0%, #fee140 100%)',
    galaxy: 'linear-gradient(135deg, #6a11cb 0%, #2575fc 100%)',
    cotton: 'linear-gradient(135deg, #ffecd2 0%, #fcb69f 100%)'
};
const DEFAULT_BODY_BG = THEME_GRADIENTS.pastel;
const DARK_BODY_BG = 'linear-gradient(135deg, #1a1a2e 0%, #16213e 100%)';

function getBodyBg(settings) {
    if (!settings) return DEFAULT_BODY_BG;
    if (settings.darkMode) return DARK_BODY_BG;
    // Prefer selected theme so "Warm Sunset" etc. apply; custom colors only when theme is not a preset
    const theme = settings.theme || 'pastel';
    if (THEME_GRADIENTS[theme]) return THEME_GRADIENTS[theme];
    const c = settings.customColors;
    if (c && c.bgGradient1 && c.bgGradient2)
        return `linear-gradient(135deg, ${c.bgGradient1} 0%, ${c.bgGradient2} 100%)`;
    return DEFAULT_BODY_BG;
}

// Middleware functions
function checkPassword(req, res, next) {
    if (req.session.passwordCorrect) {
        next();
    } else {
        res.redirect('/password');
    }
}

function checkLogin(req, res, next) {
    if (req.session.loggedIn) {
        next();
    } else {
        res.redirect('/login');
    }
}

function checkSuperAdmin(req, res, next) {
    if (req.session.isSuperAdmin) {
        next();
    } else {
        res.status(403).send('Access denied. Super Admin only.');
    }
}

// Routes
app.get('/', (req, res) => {
    if (req.session.passwordCorrect && req.session.loggedIn) {
        res.redirect('/app');
    } else if (req.session.passwordCorrect) {
        res.redirect('/login');
    } else {
        res.redirect('/password');
    }
});

app.get('/password', (req, res) => {
    if (req.session.passwordCorrect) {
        res.redirect('/login');
    } else {
        res.render('password');
    }
});

app.post('/check-password', (req, res) => {
    const { password } = req.body;
    const appPassword = process.env.APP_PASSWORD;
    if (!appPassword) {
        console.error('APP_PASSWORD environment variable is not set');
        return res.status(500).json({ success: false, message: 'Server configuration error' });
    }
    if (password === appPassword) {
        req.session.passwordCorrect = true;
        res.json({ success: true });
    } else {
        res.json({ success: false });
    }
});

app.get('/login', checkPassword, (req, res) => {
    if (req.session.loggedIn) {
        res.redirect('/app');
    } else {
        res.render('login');
    }
});

app.post('/login', checkPassword, (req, res) => {
    const { adminUsername, adminPassword } = req.body;
    
    if (bannedUsers.includes(adminUsername)) {
        return res.json({ success: false, message: 'Account banned!' });
    }
    
    const user = users[adminUsername];
    if (!user) {
        return res.json({ success: false, message: 'Invalid credentials!' });
    }
    
    if (!user.password) {
        console.error(`Login failed for ${adminUsername}: password env var not set`);
        return res.json({ success: false, message: 'Server configuration error. Contact admin.' });
    }
    
    if (user.password === adminPassword) {
        req.session.loggedIn = true;
        req.session.username = adminUsername;
        req.session.isAdmin = user.isAdmin || false;
        req.session.isSuperAdmin = user.isSuperAdmin || false;
        
        if (!userSettings[adminUsername]) {
            userSettings[adminUsername] = {
                theme: 'pastel',
                darkMode: false,
                customColors: {}
            };
        }
        
        res.json({ success: true });
    } else {
        res.json({ success: false, message: 'Invalid credentials!' });
    }
});

app.get('/denied', (req, res) => {
    res.render('denied');
});

app.get('/app', checkPassword, checkLogin, (req, res) => {
    const settings = userSettings[req.session.username] || {};
    res.render('app', {
        username: req.session.username,
        isAdmin: req.session.isAdmin,
        isSuperAdmin: req.session.isSuperAdmin,
        darkMode: settings.darkMode || false,
        bodyBg: getBodyBg(settings),
        ownerMessage: ownerBroadcast.text || ''
    });
});

app.get('/chat', checkPassword, checkLogin, (req, res) => {
    const settings = userSettings[req.session.username] || {};
    res.render('chat', {
        username: req.session.username,
        isAdmin: req.session.isAdmin,
        isSuperAdmin: req.session.isSuperAdmin,
        darkMode: settings.darkMode || false,
        bodyBg: getBodyBg(settings),
        ownerMessage: ownerBroadcast.text || ''
    });
});

app.get('/ai-assistant', checkPassword, checkLogin, (req, res) => {
    const settings = userSettings[req.session.username] || {};
    res.render('ai-assistant', {
        username: req.session.username,
        isAdmin: req.session.isAdmin,
        darkMode: settings.darkMode || false,
        bodyBg: getBodyBg(settings),
        ownerMessage: ownerBroadcast.text || ''
    });
});

app.get('/voice-chat', checkPassword, checkLogin, (req, res) => {
    const settings = userSettings[req.session.username] || {};
    res.render('voice-chat', {
        username: req.session.username,
        isAdmin: req.session.isAdmin,
        isSuperAdmin: req.session.isSuperAdmin,
        darkMode: settings.darkMode || false,
        bodyBg: getBodyBg(settings),
        ownerMessage: ownerBroadcast.text || ''
    });
});

app.get('/settings', checkPassword, checkLogin, (req, res) => {
    const settings = userSettings[req.session.username] || {};
    res.render('settings', {
        username: req.session.username,
        settings: settings,
        darkMode: settings.darkMode || false,
        customBg: settings.customColors.bgGradient1 || null,
        ownerMessage: ownerBroadcast.text || ''
    });
});

app.post('/save-settings', checkPassword, checkLogin, (req, res) => {
    const username = req.session.username;
    userSettings[username] = req.body;
    res.json({ success: true });
});

app.get('/admin-panel', checkPassword, checkLogin, checkSuperAdmin, (req, res) => {
    const settings = userSettings[req.session.username] || {};
    const userList = Object.keys(users).map(username => ({
        username,
        isAdmin: users[username].isAdmin || false,
        isSuperAdmin: users[username].isSuperAdmin || false,
        banned: bannedUsers.includes(username)
    }));
    res.render('admin-panel', {
        username: req.session.username,
        users: userList,
        scanRequests: scanRequests.slice(0, 50),
        darkMode: settings.darkMode || false,
        bodyBg: getBodyBg(settings),
        ownerMessage: ownerBroadcast.text || ''
    });
});

app.post('/api/scan-requests-clear', checkPassword, checkLogin, (req, res) => {
    if (req.session.username !== 'REZ67') {
        return res.status(403).json({ error: 'Forbidden' });
    }
    scanRequests.length = 0;
    res.json({ success: true });
});

app.post('/api/owner-broadcast', checkPassword, checkLogin, express.json(), (req, res) => {
    if (req.session.username !== 'REZ67') {
        return res.status(403).json({ error: 'Forbidden' });
    }
    const message = (req.body && req.body.message) ? String(req.body.message).trim() : '';
    ownerBroadcast = { text: message, updatedAt: new Date() };
    res.json({ success: true, message: ownerBroadcast.text });
});

app.post('/create-user', checkPassword, checkLogin, checkSuperAdmin, (req, res) => {
    const { username, password, isAdmin } = req.body;
    
    if (users[username]) {
        return res.json({ success: false, message: 'Username already exists!' });
    }
    
    users[username] = {
        password,
        isAdmin: isAdmin === 'true',
        isSuperAdmin: false
    };
    
    res.json({ success: true });
});

app.post('/ban-user', checkPassword, checkLogin, checkSuperAdmin, (req, res) => {
    const { username } = req.body;
    
    if (username === 'REZ67' || username === 'shmeckles67') {
        return res.json({ success: false, message: 'Cannot ban super admin!' });
    }
    
    if (!bannedUsers.includes(username)) {
        bannedUsers.push(username);
    }
    
    res.json({ success: true });
});

app.post('/unban-user', checkPassword, checkLogin, checkSuperAdmin, (req, res) => {
    const { username } = req.body;
    const index = bannedUsers.indexOf(username);
    
    if (index > -1) {
        bannedUsers.splice(index, 1);
    }
    
    res.json({ success: true });
});

app.post('/delete-user', checkPassword, checkLogin, checkSuperAdmin, (req, res) => {
    const { username } = req.body;
    
    if (username === 'REZ67' || username === 'shmeckles67') {
        return res.json({ success: false, message: 'Cannot delete super admin!' });
    }
    
    delete users[username];
    const index = bannedUsers.indexOf(username);
    if (index > -1) {
        bannedUsers.splice(index, 1);
    }
    
    res.json({ success: true });
});

app.post('/promote-user', checkPassword, checkLogin, checkSuperAdmin, (req, res) => {
    const { username } = req.body;
    
    if (users[username]) {
        users[username].isAdmin = true;
        res.json({ success: true });
    } else {
        res.json({ success: false, message: 'User not found!' });
    }
});

app.post('/demote-user', checkPassword, checkLogin, checkSuperAdmin, (req, res) => {
    const { username } = req.body;
    
    if (username === 'REZ67' || username === 'shmeckles67') {
        return res.json({ success: false, message: 'Cannot demote super admin!' });
    }
    
    if (users[username]) {
        users[username].isAdmin = false;
        res.json({ success: true });
    } else {
        res.json({ success: false, message: 'User not found!' });
    }
});

// Calendar route
app.get('/calendar', checkPassword, checkLogin, (req, res) => {
    const settings = userSettings[req.session.username] || {};
    res.render('calendar', {
        username: req.session.username,
        isAdmin: req.session.isAdmin,
        darkMode: settings.darkMode || false,
        bodyBg: getBodyBg(settings),
        ownerMessage: ownerBroadcast.text || ''
    });
});

// Music route
app.get('/music', checkPassword, checkLogin, (req, res) => {
    const settings = userSettings[req.session.username] || {};
    res.render('music', {
        username: req.session.username,
        isAdmin: req.session.isAdmin,
        darkMode: settings.darkMode || false,
        bodyBg: getBodyBg(settings),
        ownerMessage: ownerBroadcast.text || ''
    });
});

// Code Playground route
app.get('/playground', checkPassword, checkLogin, (req, res) => {
    const settings = userSettings[req.session.username] || {};
    res.render('playground', {
        username: req.session.username,
        isAdmin: req.session.isAdmin,
        darkMode: settings.darkMode || false,
        bodyBg: getBodyBg(settings),
        ownerMessage: ownerBroadcast.text || ''
    });
});

// Background audio popup (persists across app navigation so audio doesn't restart)
app.get('/background-player', checkPassword, checkLogin, (req, res) => {
    res.render('background-player');
});

// Scan & Answer (document Q&A) – only REZ67 can use API; others see "ask owner" and are logged for admin
app.get('/scan', checkPassword, checkLogin, (req, res) => {
    const username = req.session.username;
    const settings = userSettings[username] || {};
    const canUseScanner = username === 'REZ67';
    if (!canUseScanner) {
        scanRequests.unshift({ username, at: new Date().toISOString() });
        if (scanRequests.length > 100) scanRequests.pop();
    }
    res.render('scan', {
        username,
        canUseScanner,
        darkMode: settings.darkMode || false,
        bodyBg: getBodyBg(settings),
        ownerMessage: ownerBroadcast.text || ''
    });
});

const SCAN_PROMPT = `You are extracting questions and answers from a document. List EVERY question you can find and give ONLY the direct short answer (no explanation, no extra text). Format strictly like this, one per line:
1. Q: [exact question] A: [short answer]
2. Q: [exact question] A: [short answer]
Continue numbering. If there are no clear questions, summarize key facts as brief Q&A pairs. Output nothing else.`;

app.post('/api/scan-document', checkPassword, checkLogin, async (req, res) => {
    if (req.session.username !== 'REZ67') {
        return res.status(403).json({ error: 'Only the owner (REZ67) can use the scanner API.' });
    }
    let text = (req.body && req.body.text) || '';
    const provider = (req.body && req.body.provider) || 'claude';
    const apiKey = (req.body && req.body.apiKey) || '';
    if (!apiKey.trim()) {
        return res.status(400).json({ error: 'API key required' });
    }
    if (!text.trim()) {
        return res.status(400).json({ error: 'No text to scan. Upload a PDF or paste text.' });
    }
    text = text.slice(0, 120000);
    const prompt = `${SCAN_PROMPT}\n\n--- DOCUMENT ---\n${text}\n--- END ---`;
    try {
        const fetch = (await import('node-fetch')).default;
        let response;
        if (provider === 'claude') {
            response = await fetch('https://api.anthropic.com/v1/messages', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'x-api-key': apiKey,
                    'anthropic-version': '2023-06-01'
                },
                body: JSON.stringify({
                    model: 'claude-sonnet-4-20250514',
                    max_tokens: 4096,
                    messages: [{ role: 'user', content: prompt }]
                })
            });
        } else {
            response = await fetch('https://api.openai.com/v1/chat/completions', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${apiKey}`
                },
                body: JSON.stringify({
                    model: 'gpt-4o',
                    max_tokens: 4096,
                    messages: [{ role: 'user', content: prompt }]
                })
            });
        }
        const data = await response.json();
        if (provider === 'claude') {
            const content = data.content && data.content[0];
            const msg = content && content.text ? content.text : (data.error && data.error.message) || JSON.stringify(data);
            return res.json({ answer: msg, error: data.error ? true : false });
        }
        const msg = data.choices && data.choices[0] && data.choices[0].message
            ? data.choices[0].message.content
            : (data.error && data.error.message) || JSON.stringify(data);
        res.json({ answer: msg, error: data.error ? true : false });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/scan-document-upload', checkPassword, checkLogin, upload.single('file'), async (req, res) => {
    if (req.session.username !== 'REZ67') {
        return res.status(403).json({ error: 'Only the owner (REZ67) can use the scanner.' });
    }
    if (!req.file) {
        return res.status(400).json({ error: 'No PDF file uploaded' });
    }
    let text = '';
    try {
        const dataBuffer = fs.readFileSync(req.file.path);
        const data = await pdfParse(dataBuffer);
        text = (data && data.text) || '';
        fs.unlink(req.file.path, () => {});
    } catch (e) {
        try { fs.unlinkSync(req.file.path); } catch (_) {}
        return res.status(400).json({ error: 'Could not read PDF: ' + (e.message || 'invalid file') });
    }
    if (!text.trim()) {
        return res.status(400).json({ error: 'No text found in PDF' });
    }
    res.json({ text: text.slice(0, 120000) });
});

// AI Assistant proxy
app.post('/api/ai', checkPassword, checkLogin, async (req, res) => {
    const { provider, apiKey, prompt } = req.body;
    
    try {
        const fetch = (await import('node-fetch')).default;
        let response;
        
        if (provider === 'claude') {
            response = await fetch('https://api.anthropic.com/v1/messages', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'x-api-key': apiKey,
                    'anthropic-version': '2023-06-01'
                },
                body: JSON.stringify({
                    model: 'claude-sonnet-4-20250514',
                    max_tokens: 1024,
                    messages: [{ role: 'user', content: prompt }]
                })
            });
        } else if (provider === 'openai') {
            response = await fetch('https://api.openai.com/v1/chat/completions', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${apiKey}`
                },
                body: JSON.stringify({
                    model: 'gpt-5',
                    messages: [{ role: 'user', content: prompt }]
                })
            });
        }
        
        const data = await response.json();
        res.json(data);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/logout', (req, res) => {
    const username = req.session.username;
    if (username && onlineUsers.has(username)) {
        onlineUsers.delete(username);
        io.emit('user-left', { username, onlineUsers: Array.from(onlineUsers.keys()) });
    }
    req.session.destroy();
    res.redirect('/password');
});

app.post('/logout-immediate', (req, res) => {
    const username = req.session.username;
    if (username && onlineUsers.has(username)) {
        onlineUsers.delete(username);
        io.emit('user-left', { username, onlineUsers: Array.from(onlineUsers.keys()) });
    }
    req.session.destroy();
    res.sendStatus(200);
});

// Socket.IO connection
io.on('connection', (socket) => {
    console.log('✅ New client connected:', socket.id);
    
    socket.on('register-user', (username) => {
        console.log(`📝 Registering user: ${username}`);
        socket.username = username;
        onlineUsers.set(username, socket.id);
        io.emit('online-users', Array.from(onlineUsers.keys()));
        
        // Send message history
        socket.emit('message-history', messages);
        
        // Send private message history if super admin
        if (username === 'REZ67' || username === 'shmeckles67') {
            socket.emit('private-message-history', privateMessages);
        }
        
        console.log(`✅ ${username} is now online`);
    });
    
    socket.on('chat-message', (data) => {
        console.log('💬 Chat message received:', data);
        const message = {
            username: data.username,
            message: data.message,
            timestamp: new Date().toISOString(),
            isAdmin: users[data.username]?.isAdmin || false
        };
        
        messages.push(message);
        if (messages.length > 100) messages.shift();
        
        io.emit('chat-message', message);
    });
    
    socket.on('private-message', (data) => {
        console.log('🔒 Private message received:', data);
        const message = {
            username: data.username,
            message: data.message,
            timestamp: new Date().toISOString(),
            isAdmin: users[data.username]?.isAdmin || false
        };
        
        privateMessages.push(message);
        if (privateMessages.length > 100) privateMessages.shift();
        
        // Only send to REZ67 and shmeckles67
        const rez67Socket = onlineUsers.get('REZ67');
        const shmecklesSocket = onlineUsers.get('shmeckles67');
        
        if (rez67Socket) {
            io.to(rez67Socket).emit('private-message', message);
        }
        if (shmecklesSocket) {
            io.to(shmecklesSocket).emit('private-message', message);
        }
    });
    
    socket.on('typing', (data) => {
        socket.broadcast.emit('typing', data);
    });
    
    // Task management
    socket.on('get-tasks', (username) => {
        console.log(`📅 Getting tasks for: ${username}`);
        const userTasks = tasks[username] || [];
        socket.emit('tasks-updated', userTasks);
    });
    
    socket.on('add-task', (task) => {
        console.log('➕ Adding task:', task);
        const username = task.username;
        if (!tasks[username]) {
            tasks[username] = [];
        }
        tasks[username].push(task);
        
        // Send updated tasks to the user
        const userSocket = onlineUsers.get(username);
        if (userSocket) {
            io.to(userSocket).emit('tasks-updated', tasks[username]);
        }
    });
    
    socket.on('toggle-task', (data) => {
        console.log('✅ Toggling task:', data);
        const { taskId, username } = data;
        if (tasks[username]) {
            const task = tasks[username].find(t => t.id === taskId);
            if (task) {
                task.completed = !task.completed;
                
                const userSocket = onlineUsers.get(username);
                if (userSocket) {
                    io.to(userSocket).emit('tasks-updated', tasks[username]);
                }
            }
        }
    });
    
    socket.on('delete-task', (data) => {
        console.log('🗑️ Deleting task:', data);
        const { taskId, username } = data;
        if (tasks[username]) {
            tasks[username] = tasks[username].filter(t => t.id !== taskId);
            
            const userSocket = onlineUsers.get(username);
            if (userSocket) {
                io.to(userSocket).emit('tasks-updated', tasks[username]);
            }
        }
    });
    
    // Music management
    socket.on('upload-song', (song) => {
        console.log('🎵 Uploading song for:', song.username);
        const username = song.username;
        if (!userSongs[username]) {
            userSongs[username] = [];
        }
        userSongs[username].push(song);
        // Always notify the uploader so their library updates
        socket.emit('songs-updated', userSongs[username]);
    });
    
    socket.on('get-my-songs', (username) => {
        console.log('📥 Getting songs for:', username);
        const songs = userSongs[username] || [];
        const userSocket = onlineUsers.get(username);
        if (userSocket) {
            io.to(userSocket).emit('songs-updated', songs);
        }
    });
    
    socket.on('delete-song', (data) => {
        console.log('🗑️ Deleting song:', data);
        const { songId, username } = data;
        if (userSongs[username]) {
            userSongs[username] = userSongs[username].filter(s => s.id !== songId);
            
            const userSocket = onlineUsers.get(username);
            if (userSocket) {
                io.to(userSocket).emit('songs-updated', userSongs[username]);
            }
        }
    });
    
    // Album management
    socket.on('get-albums', (username) => {
        console.log('📀 Getting albums for:', username);
        const myAlbums = musicAlbums.filter(a => a.owner === username);
        const sharedAlbums = musicAlbums.filter(a => a.shared && a.owner !== username);
        
        const userSocket = onlineUsers.get(username);
        if (userSocket) {
            io.to(userSocket).emit('albums-updated', { myAlbums, sharedAlbums });
        }
    });
    
    socket.on('create-album', (album) => {
        console.log('📀 Creating album:', album.name, 'by', album.owner);
        musicAlbums.push(album);
        
        // Notify owner
        const userSocket = onlineUsers.get(album.owner);
        if (userSocket) {
            const myAlbums = musicAlbums.filter(a => a.owner === album.owner);
            const sharedAlbums = musicAlbums.filter(a => a.shared && a.owner !== album.owner);
            io.to(userSocket).emit('albums-updated', { myAlbums, sharedAlbums });
        }
        
        // Notify all users if shared
        if (album.shared) {
            onlineUsers.forEach((socketId, user) => {
                if (user !== album.owner) {
                    const sharedAlbums = musicAlbums.filter(a => a.shared && a.owner !== user);
                    io.to(socketId).emit('albums-updated', { 
                        myAlbums: musicAlbums.filter(a => a.owner === user), 
                        sharedAlbums 
                    });
                }
            });
        }
    });
    
    socket.on('delete-album', (data) => {
        console.log('🗑️ Deleting album:', data);
        const { albumId, username } = data;
        const index = musicAlbums.findIndex(a => a.id === albumId && a.owner === username);
        
        if (index > -1) {
            musicAlbums.splice(index, 1);
            
            const userSocket = onlineUsers.get(username);
            if (userSocket) {
                const myAlbums = musicAlbums.filter(a => a.owner === username);
                const sharedAlbums = musicAlbums.filter(a => a.shared && a.owner !== username);
                io.to(userSocket).emit('albums-updated', { myAlbums, sharedAlbums });
            }
        }
    });
    
    socket.on('add-song-to-album', (data) => {
        console.log('➕ Adding song to album:', data);
        const { albumId, song, username } = data;
        const album = musicAlbums.find(a => a.id === albumId && a.owner === username);
        
        if (album && !album.songs.find(s => s.id === song.id)) {
            album.songs.push(song);
            
            const userSocket = onlineUsers.get(username);
            if (userSocket) {
                const myAlbums = musicAlbums.filter(a => a.owner === username);
                const sharedAlbums = musicAlbums.filter(a => a.shared && a.owner !== username);
                io.to(userSocket).emit('albums-updated', { myAlbums, sharedAlbums });
            }
        }
    });
    
    socket.on('disconnect', () => {
        if (socket.username) {
            console.log(`❌ ${socket.username} disconnected`);
            onlineUsers.delete(socket.username);
            io.emit('user-left', {
                username: socket.username,
                onlineUsers: Array.from(onlineUsers.keys())
            });
        }
    });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`🚀 Server running on http://localhost:${PORT}`);
    console.log(`📡 Socket.IO is ready for connections`);
});                                                              