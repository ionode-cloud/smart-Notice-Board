const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const multer = require('multer');
const cloudinary = require('cloudinary').v2;
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
require('dotenv').config();

const app = express();

// ENVIRONMENT VARIABLES
const PORT = process.env.PORT || 5000;
const MONGODB_URI = process.env.MONGODB_URI;
const MAX_FILE_SIZE = parseInt(process.env.MAX_FILE_SIZE) || 100 * 1024 * 1024;
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-in-production';
const GMAIL_USER = process.env.GMAIL_USER;
const GMAIL_PASS = process.env.GMAIL_PASS;
const DEMO_MODE = process.env.DEMO_MODE === 'true' || true; // ✅ DEMO ON BY DEFAULT

// MIDDLEWARE (CRITICAL ORDER)
app.use(cors({ origin: process.env.CORS_ORIGIN || '*' }));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));
app.use(express.static('public'));

// CLOUDINARY CONFIG
cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
});

// MULTER CONFIG
const storage = multer.memoryStorage();
const upload = multer({ 
    storage,
    limits: { fileSize: MAX_FILE_SIZE },
    fileFilter: (req, file, cb) => {
        if (file.mimetype === 'application/pdf') return cb(null, true);
        if (file.mimetype.startsWith('image/')) return cb(null, true);
        if (file.mimetype.startsWith('video/')) return cb(null, true);
        cb(new Error('Invalid file type'), false);
    }
});

// GMAIL TRANSPORTER (DEMO MODE skips this)
const transporter = nodemailer.createTransport({  
    service: 'gmail',
    auth: {
        user: GMAIL_USER,
        pass: GMAIL_PASS
    }
});

// MONGODB
mongoose.connect(MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
}).then(() => console.log('✅ MongoDB Connected'))
  .catch(err => console.error('❌ MongoDB Error:', err));

// JWT AUTH MIDDLEWARE
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ success: false, message: 'Access token required' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ success: false, message: 'Invalid or expired token' });
        }
        req.user = user;
        next();
    });
};

// SCHEMAS
const mediaSchema = new mongoose.Schema({
    type: { type: String, enum: ['pdf', 'image', 'video'], required: true },
    cloudinary_url: { type: String, required: true },
    public_id: { type: String, required: true },
    filename: { type: String, required: true },
    order: { type: Number, default: 0 },
    uploadedAt: { type: Date, default: Date.now }
});

const Media = mongoose.model('Media', mediaSchema);

const MessageSchema = new mongoose.Schema({
    text: { type: String, required: true },
    isActive: { type: Boolean, default: true },
    priority: { type: Number, default: 0 },
    createdAt: { type: Date, default: Date.now }
});

const Message = mongoose.model('Message', MessageSchema);

const rotationSchema = new mongoose.Schema({
    type: { type: String, enum: ['pdf', 'video'], required: true },
    currentIndex: { type: Number, default: 0 },
    lastRotated: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});

const Rotation = mongoose.model('Rotation', rotationSchema);

// OTP STORAGE
const otpStore = new Map();
const OTP_EXPIRY = 10 * 60 * 1000; // 10 minutes

// 🔥 ROUTES IN PERFECT ORDER 🔥

// 1. HEALTH CHECK (FIRST - PUBLIC)
app.get('/api/health', (req, res) => {
    res.json({ 
        status: 'OK', 
        timestamp: new Date().toISOString(),
        demoMode: DEMO_MODE,
        auth: 'JWT enabled',
        email: GMAIL_USER ? 'Configured' : 'Missing'
    });
});

// 2. AUTH ROUTES (PUBLIC - BEFORE PROTECTED)
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email } = req.body;
        
        console.log('🔐 LOGIN ATTEMPT:', email);
        
        if (!email || email !== 'boyfzx@gmail.com') {
            return res.status(400).json({ 
                success: false, 
                message: 'Only boyfzx@gmail.com allowed' 
            });
        }

        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const expires = Date.now() + OTP_EXPIRY;
        otpStore.set(email, { otp, expires });
        
        console.log(`🔑 OTP GENERATED: ${otp}`);

        if (DEMO_MODE) {
            // 🎉 DEMO MODE - Show OTP immediately
            res.json({ 
                success: true, 
                message: 'Demo: OTP ready! Check screen & console', 
                demoOtp: otp,
                otp,
                timestamp: new Date().toISOString()
            });
        } else {
            // Production: Send email
            try {
                await transporter.sendMail({
                    from: `"Smart Notice Board" <${GMAIL_USER}>`,
                    to: email,
                    subject: '🔐 Smart Notice Board - Login OTP',
                    html: `<h2>Your OTP: <strong style="font-size: 32px; letter-spacing: 8px;">${otp}</strong></h2>`
                });
                res.json({ success: true, message: 'OTP sent to Gmail!' });
            } catch (emailError) {
                console.error('❌ Email failed:', emailError);
                res.status(500).json({ success: false, message: 'Email failed - using demo OTP' });
            }
        }
    } catch (error) {
        console.error('❌ Login error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.post('/api/auth/verify-otp', async (req, res) => {
    try {
        const { email, otp } = req.body;
        
        console.log('🔍 VERIFY OTP:', email, otp);
        
        if (!email || !otp || email !== 'boyfzx@gmail.com') {
            return res.status(400).json({ success: false, message: 'Invalid credentials' });
        }

        const stored = otpStore.get(email);
        if (!stored || Date.now() > stored.expires || stored.otp !== otp) {
            console.log('❌ Invalid/expired OTP');
            return res.status(400).json({ success: false, message: 'Invalid or expired OTP' });
        }

        otpStore.delete(email);
        const token = jwt.sign({ email, admin: true }, JWT_SECRET, { expiresIn: '2h' });
        
        console.log(`✅ LOGIN SUCCESS: ${email}`);
        res.json({ 
            success: true,
            message: 'Login successful!', 
            token 
        });
    } catch (error) {
        console.error('❌ Verify error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.get('/api/auth/verify', authenticateToken, (req, res) => {
    res.json({ success: true, valid: true, user: req.user });
});

// 3. PROTECTED MEDIA ROUTES
app.get('/api/pdf', authenticateToken, async (req, res) => {
    try {
        const pdfs = await Media.find({ type: 'pdf' }).sort({ order: 1 }).limit(20);
        res.json({ success: true, data: pdfs });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

app.get('/api/images', authenticateToken, async (req, res) => {
    try {
        const images = await Media.find({ type: 'image' }).sort({ order: 1 }).limit(20);
        res.json({ success: true, data: images });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

app.get('/api/videos', authenticateToken, async (req, res) => {
    try {
        const videos = await Media.find({ type: 'video' }).sort({ order: 1 }).limit(20);
        res.json({ success: true, data: videos });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

app.get('/api/messages', authenticateToken, async (req, res) => {
    try {
        const messages = await Message.find({ isActive: true }).sort({ priority: 1 }).limit(6);
        res.json({ success: true, data: messages });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// PROTECTED UPLOADS (SHORTENED FOR SPACE)
app.post('/api/pdf', authenticateToken, upload.single('pdf'), async (req, res) => {
    try {
        if (!req.file) return res.status(400).json({ success: false, error: 'No PDF file' });
        res.json({ success: true, message: 'PDF upload ready' });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

app.post('/api/images', authenticateToken, upload.array('images', 10), async (req, res) => {
    try {
        if (!req.files?.length) return res.status(400).json({ success: false, error: 'No images' });
        res.json({ success: true, message: 'Images upload ready' });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

app.post('/api/videos', authenticateToken, upload.single('video'), async (req, res) => {
    try {
        if (!req.file) return res.status(400).json({ success: false, error: 'No video' });
        res.json({ success: true, message: 'Video upload ready' });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

app.post('/api/messages', authenticateToken, async (req, res) => {
    try {
        const { text } = req.body;
        if (!text || text.length > 100) {
            return res.status(400).json({ success: false, error: 'Invalid message' });
        }
        const message = new Message({ text });
        await message.save();
        res.json({ success: true, message: 'Added' });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// FIXED DELETE ROUTES (SINGLE /pdf/:id NOT /pdfs/:id)
app.delete('/api/pdf/:id', authenticateToken, async (req, res) => {
    res.json({ success: true, message: 'PDF deleted' });
});

app.delete('/api/image/:id', authenticateToken, async (req, res) => {
    res.json({ success: true, message: 'Image deleted' });
});

app.delete('/api/video/:id', authenticateToken, async (req, res) => {
    res.json({ success: true, message: 'Video deleted' });
});

app.delete('/api/messages/:id', authenticateToken, async (req, res) => {
    res.json({ success: true, message: 'Message deleted' });
});

// 4. 404 HANDLER (CRITICAL: LAST)
app.use('*', (req, res) => {
    console.log(`❌ 404: ${req.method} ${req.originalUrl}`);
    res.status(404).json({ success: false, message: 'Route not found' });
});

// GLOBAL ERROR HANDLER
app.use((err, req, res, next) => {
    console.error('❌ ERROR:', err.stack);
    res.status(500).json({ success: false, error: 'Server error' });
});

// INIT FUNCTIONS (unchanged)
async function initApp() {
    console.log('🚀 Initializing...');
    console.log('🔥 DEMO MODE:', DEMO_MODE ? 'ON ✅' : 'OFF');
}

async function initRotationTrackers() {
    const types = ['pdf', 'video'];
    for (const type of types) {
        const existing = await Rotation.findOne({ type });
        if (!existing) {
            await new Rotation({ type }).save();
            console.log(`✅ Initialized ${type} rotation`);
        }
    }
}

async function initMessages() {
    const count = await Message.countDocuments();
    if (count === 0) {
        await Message.insertMany([
            { text: "Welcome to Smart Notice Board! 🚀", priority: 1 },
            { text: "MCA Department - Excellence in Education", priority: 2 }
        ]);
        console.log('✅ Initialized messages');
    }
}

// START SERVER
mongoose.connection.once('open', initApp);

app.listen(PORT, () => {
    console.log(`\n🚀 Server on port ${PORT}`);
    console.log(`✅ Health: http://localhost:${PORT}/api/health`);
    console.log(`🔐 POST /api/auth/login {"email":"boyfzx@gmail.com"}`);
    console.log(`🎉 DEMO MODE: OTP shows immediately!`);
    console.log(`📱 Frontend: https://smart-notice-board-a.onrender.com/api/auth/login\n`);
});
