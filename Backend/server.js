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

// MIDDLEWARE
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

// GMAIL TRANSPORTER
// GMAIL TRANSPORTER - CORRECTED (Line 48)
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
        return res.status(401).json({ message: 'Access token required' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ message: 'Invalid or expired token' });
        }
        req.user = user;
        next();
    });
};

// MEDIA SCHEMA
const mediaSchema = new mongoose.Schema({
    type: { type: String, enum: ['pdf', 'image', 'video'], required: true },
    cloudinary_url: { type: String, required: true },
    public_id: { type: String, required: true },
    filename: { type: String, required: true },
    order: { type: Number, default: 0 },
    uploadedAt: { type: Date, default: Date.now }
});

const Media = mongoose.model('Media', mediaSchema);

// MARQUEE MESSAGE SCHEMA
const Message = mongoose.model('Message', new mongoose.Schema({
    text: { type: String, required: true },
    isActive: { type: Boolean, default: true },
    priority: { type: Number, default: 0 },
    createdAt: { type: Date, default: Date.now }
}));

// ROTATION TRACKER SCHEMA
const rotationSchema = new mongoose.Schema({
    type: { type: String, enum: ['pdf', 'video'], required: true },
    currentIndex: { type: Number, default: 0 },
    lastRotated: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});

const Rotation = mongoose.model('Rotation', rotationSchema);

// OTP STORAGE (in-memory, use Redis for production)
const otpStore = new Map();
const OTP_EXPIRY = 10 * 60 * 1000; // 10 minutes

// Initialize everything
async function initApp() {
    await initRotationTrackers();
    await initMessages();
    console.log('🚀 App fully initialized');
}

async function initRotationTrackers() {
    const types = ['pdf', 'video'];
    for (const type of types) {
        const existing = await Rotation.findOne({ type });
        if (!existing) {
            await new Rotation({ type }).save();
            console.log(`✅ Initialized ${type} rotation tracker`);
        }
    }
}

async function initMessages() {
    const count = await Message.countDocuments();
    if (count === 0) {
        await Message.insertMany([
            { text: "Welcome to Smart Notice Board! 🚀", priority: 1 },
            { text: "MCA Department - Excellence in Education", priority: 2 },
            { text: "Latest Placement Updates Available", priority: 3 },
            { text: "📚 Library Open 24/7 - Study Hard!", priority: 4 }
        ]);
        console.log('✅ Initialized marquee messages');
    }
}

// REINDEX FUNCTION
async function reindexMedia(type) {
    const media = await Media.find({ type }).sort({ order: 1 });
    await Promise.all(media.map((item, index) => 
        Media.updateOne({ _id: item._id }, { order: index })
    ));
}

// ========== AUTH ROUTES ==========
app.post('/api/auth/login', async (req, res) => {
    const { email } = req.body;
    
    // Only allow admin email
    if (email !== 'boyfzx@gmail.com') {
        return res.status(401).json({ message: 'Invalid email address' });
    }
    
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expires = Date.now() + OTP_EXPIRY;
    
    otpStore.set(email, { otp, expires });
    
    try {
        await transporter.sendMail({
            from: `"Smart Notice Board" <${GMAIL_USER}>`,
            to: email,
            subject: '🔐 Smart Notice Board - Login OTP',
            html: `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                    <h2 style="color: #2563eb;">Login Verification</h2>
                    <p>Your <strong>6-digit OTP</strong> is:</p>
                    <div style="background: #2563eb; color: white; font-size: 32px; font-weight: bold; 
                                padding: 20px; text-align: center; border-radius: 12px; 
                                letter-spacing: 8px; margin: 20px 0;">
                        ${otp}
                    </div>
                    <p style="color: #666;">
                        <strong>This OTP expires in 10 minutes.</strong><br>
                        Enter it on the login page to access admin panel.
                    </p>
                    <hr style="border: none; border-top: 1px solid #eee; margin: 30px 0;">
                    <p style="color: #999; font-size: 12px;">
                        If you didn't request this, please ignore this email.<br>
                        Smart Notice Board Admin Panel
                    </p>
                </div>
            `
        });
        
        console.log(`✅ OTP sent to ${email}`);
        res.json({ message: 'OTP sent to your Gmail! Check your inbox.' });
    } catch (error) {
        console.error('❌ Email error:', error);
        res.status(500).json({ message: 'Failed to send OTP. Check server logs.' });
    }
});

app.post('/api/auth/forgot-password', async (req, res) => {
    const { email } = req.body;
    
    if (email !== 'boyfzx@gmail.com') {
        return res.status(401).json({ message: 'Invalid email address' });
    }
    
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expires = Date.now() + OTP_EXPIRY;
    
    otpStore.set(email, { otp, expires });
    
    try {
        await transporter.sendMail({
            from: `"Smart Notice Board" <${GMAIL_USER}>`,
            to: email,
            subject: '🔑 Smart Notice Board - Reset OTP',
            html: `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                    <h2 style="color: #2563eb;">Password Reset Verification</h2>
                    <p>Your <strong>6-digit OTP</strong> is:</p>
                    <div style="background: #2563eb; color: white; font-size: 32px; font-weight: bold; 
                                padding: 20px; text-align: center; border-radius: 12px; 
                                letter-spacing: 8px; margin: 20px 0;">
                        ${otp}
                    </div>
                    <p style="color: #666;">
                        <strong>This OTP expires in 10 minutes.</strong><br>
                        Use it to reset your admin access.
                    </p>
                </div>
            `
        });
        
        console.log(`✅ Reset OTP sent to ${email}`);
        res.json({ message: 'Reset OTP sent to your Gmail!' });
    } catch (error) {
        console.error('❌ Email error:', error);
        res.status(500).json({ message: 'Failed to send OTP' });
    }
});

app.post('/api/auth/verify-otp', (req, res) => {
    const { email, otp } = req.body;
    
    const stored = otpStore.get(email);
    if (!stored || Date.now() > stored.expires || stored.otp !== otp) {
        return res.status(400).json({ message: 'Invalid or expired OTP' });
    }
    
    // Clear OTP after successful verification
    otpStore.delete(email);
    
    // Generate JWT (2 hour expiry)
    const token = jwt.sign({ email }, JWT_SECRET, { expiresIn: '2h' });
    
    console.log(`✅ Admin logged in: ${email}`);
    res.json({ 
        message: 'Login successful! Redirecting...',
        token 
    });
});

app.get('/api/auth/verify', authenticateToken, (req, res) => {
    res.json({ valid: true, user: req.user });
});

// ========== PROTECTED MEDIA ROUTES ==========
app.get('/api/pdf', authenticateToken, async (req, res) => {
    try {
        const pdfs = await Media.find({ type: 'pdf' })
            .sort({ order: 1, uploadedAt: 1 })
            .limit(20);
        res.json(pdfs);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/videos', authenticateToken, async (req, res) => {
    try {
        const videos = await Media.find({ type: 'video' })
            .sort({ order: 1, uploadedAt: 1 })
            .limit(20);
        res.json(videos);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/images', authenticateToken, async (req, res) => {
    try {
        const images = await Media.find({ type: 'image' })
            .sort({ order: 1, uploadedAt: 1 })
            .limit(20);
        res.json(images);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/messages', authenticateToken, async (req, res) => {
    try {
        const messages = await Message.find({ isActive: true })
            .sort({ priority: 1, createdAt: -1 })
            .limit(6);
        
        if (messages.length === 0) {
            return res.json([
                { text: "📢 Welcome to Smart Notice Board! 🚀" },
                { text: "🎓 All systems operational" }
            ]);
        }
        
        res.json(messages);
    } catch (error) {
        res.status(500).json({ error: 'Messages unavailable' });
    }
});

// PROTECTED UPLOAD ENDPOINTS
app.post('/api/pdf', authenticateToken, upload.single('pdf'), async (req, res) => {
    try {
        if (!req.file) return res.status(400).json({ error: 'No PDF file' });

        const result = await new Promise((resolve, reject) => {
            const uploadStream = cloudinary.uploader.upload_stream(
                { resource_type: 'raw', folder: 'noticeboard/pdf' },
                (error, result) => error ? reject(error) : resolve(result)
            );
            uploadStream.end(req.file.buffer);
        });

        const maxOrder = await Media.findOne({ type: 'pdf' })
            .sort({ order: -1 }).select('order') || { order: 0 };

        const media = new Media({
            type: 'pdf',
            cloudinary_url: result.secure_url,
            public_id: result.public_id,
            filename: req.file.originalname,
            order: maxOrder.order + 1
        });

        await media.save();
        res.json(media);
    } catch (error) {
        console.error('PDF error:', error);
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/images', authenticateToken, upload.array('images', 10), async (req, res) => {
    try {
        if (!req.files?.length) return res.status(400).json({ error: 'No images' });

        const maxOrder = await Media.findOne({ type: 'image' })
            .sort({ order: -1 }).select('order') || { order: 0 };

        const uploadPromises = req.files.map(file =>
            new Promise((resolve, reject) => {
                const uploadStream = cloudinary.uploader.upload_stream(
                    { folder: 'noticeboard/images' },
                    (error, result) => error ? reject(error) : resolve(result)
                );
                uploadStream.end(file.buffer);
            })
        );

        const results = await Promise.all(uploadPromises);
        const mediaItems = results.map((result, index) => ({
            type: 'image',
            cloudinary_url: result.secure_url,
            public_id: result.public_id,
            filename: req.files[index].originalname,
            order: maxOrder.order + 1 + index
        }));

        const savedMedia = await Media.insertMany(mediaItems);
        res.json(savedMedia);
    } catch (error) {
        console.error('Images error:', error);
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/videos', authenticateToken, upload.single('video'), async (req, res) => {
    try {
        if (!req.file) return res.status(400).json({ error: 'No video' });

        const result = await new Promise((resolve, reject) => {
            const uploadStream = cloudinary.uploader.upload_stream(
                { resource_type: 'video', folder: 'noticeboard/videos' },
                (error, result) => error ? reject(error) : resolve(result)
            );
            uploadStream.end(req.file.buffer);
        });

        const maxOrder = await Media.findOne({ type: 'video' })
            .sort({ order: -1 }).select('order') || { order: 0 };

        const media = new Media({
            type: 'video',
            cloudinary_url: result.secure_url,
            public_id: result.public_id,
            filename: req.file.originalname,
            order: maxOrder.order + 1
        });

        await media.save();
        res.json(media);
    } catch (error) {
        console.error('Video error:', error);
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/messages', authenticateToken, async (req, res) => {
    try {
        const { text } = req.body;
        if (!text || text.length > 100) {
            return res.status(400).json({ error: 'Invalid message (max 100 chars)' });
        }
        
        const message = new Message({ text });
        await message.save();
        res.json({ message: 'Message added successfully' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// PROTECTED DELETE ENDPOINTS
app.delete('/api/pdfs/:id', authenticateToken, async (req, res) => {
    try {
        const media = await Media.findByIdAndDelete(req.params.id);
        if (!media) return res.status(404).json({ error: 'PDF not found' });
        await cloudinary.uploader.destroy(media.public_id);
        await reindexMedia('pdf');
        res.json({ message: 'PDF deleted' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.delete('/api/images/:id', authenticateToken, async (req, res) => {
    try {
        const media = await Media.findByIdAndDelete(req.params.id);
        if (!media) return res.status(404).json({ error: 'Image not found' });
        await cloudinary.uploader.destroy(media.public_id);
        await reindexMedia('image');
        res.json({ message: 'Image deleted' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.delete('/api/videos/:id', authenticateToken, async (req, res) => {
    try {
        const media = await Media.findByIdAndDelete(req.params.id);
        if (!media) return res.status(404).json({ error: 'Video not found' });
        await cloudinary.uploader.destroy(media.public_id, { resource_type: 'video' });
        await reindexMedia('video');
        res.json({ message: 'Video deleted' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.delete('/api/messages/:id', authenticateToken, async (req, res) => {
    try {
        await Message.findByIdAndDelete(req.params.id);
        res.json({ message: 'Message deleted' });
    } catch (error) {
        res.status(500).json({ error: 'Delete failed' });
    }
});

// PROTECTED ORDER UPDATE ENDPOINTS
app.patch('/api/pdfs', authenticateToken, async (req, res) => {
    try {
        const { order } = req.body;
        await Promise.all(order.map((id, index) => 
            Media.updateOne({ _id: id }, { order: index })
        ));
        await Rotation.updateOne({ type: 'pdf' }, { currentIndex: 0 });
        res.json({ message: 'PDF order updated' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.patch('/api/images', authenticateToken, async (req, res) => {
    try {
        const { order } = req.body;
        await Promise.all(order.map((id, index) => 
            Media.updateOne({ _id: id }, { order: index })
        ));
        res.json({ message: 'Image order updated' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.patch('/api/videos', authenticateToken, async (req, res) => {
    try {
        const { order } = req.body;
        await Promise.all(order.map((id, index) => 
            Media.updateOne({ _id: id }, { order: index })
        ));
        await Rotation.updateOne({ type: 'video' }, { currentIndex: 0 });
        res.json({ message: 'Video order updated' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// HEALTH CHECK (public)
app.get('/api/health', (req, res) => {
    res.json({ 
        status: 'OK', 
        timestamp: new Date().toISOString(),
        auth: 'JWT enabled',
        email: GMAIL_USER ? 'Configured' : 'Missing'
    });
});

// GLOBAL ERROR HANDLER
app.use((err, req, res, next) => {
    console.error('❌ Server Error:', err.stack);
    res.status(500).json({ error: 'Something went wrong!', details: err.message });
});

// START SERVER
mongoose.connection.once('open', initApp);

app.listen(PORT, () => {
    console.log(`🚀 Server running on http://localhost:${PORT}`);
    console.log(`✅ Health: http://localhost:${PORT}/api/health`);
    console.log(`🔐 Auth enabled - Only boyfzx@gmail.com allowed`);
});
