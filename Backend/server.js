require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const multer = require('multer');
const cloudinary = require('cloudinary').v2;
const path = require('path');

const app = express();
const MAX_FILE_SIZE = 100 * 1024 * 1024;

// User Schema
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  otp: { type: String },
  otpExpires: { type: Date }
}, { timestamps: true });

const User = mongoose.model('User', userSchema);

//  MEDIA SCHEMA
const mediaSchema = new mongoose.Schema({
    type: { type: String, enum: ['pdf', 'image', 'video'], required: true },
    cloudinary_url: { type: String, required: true },
    public_id: { type: String, required: true },
    filename: { type: String, required: true },
    order: { type: Number, default: 0 },
    uploadedAt: { type: Date, default: Date.now }
});

const Media = mongoose.model('Media', mediaSchema);

//  ROTATION TRACKER SCHEMA
const rotationSchema = new mongoose.Schema({
    type: { type: String, enum: ['pdf', 'video'], required: true },
    currentIndex: { type: Number, default: 0 },
    lastRotated: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});

const Rotation = mongoose.model('Rotation', rotationSchema);

// FIXED: createTransport
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.GMAIL_USER,
    pass: process.env.GMAIL_PASS
  }
});

// Middleware
app.use(cors({
  origin: ['*','http://localhost:5000'],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json());

// JWT Middleware
const cookieParser = require('cookie-parser');
app.use(cookieParser());

const authMiddleware = (req, res, next) => {
  const token = req.cookies?.token;
  if (!token) return res.redirect('/');

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.redirect('/');
  }
};

//  CLOUDINARY CONFIG (from .env)
cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
});

//  MULTER CONFIG
const storage = multer.memoryStorage();
const upload = multer({ 
    storage,
    limits: { fileSize: 100 * 1024 * 1024 }, 
    fileFilter: (req, file, cb) => {
        if (file.mimetype === 'application/pdf') return cb(null, true);
        if (file.mimetype.startsWith('image/')) return cb(null, true);
        if (file.mimetype.startsWith('video/')) return cb(null, true);
        cb(new Error('Invalid file type'), false);
    }
});

//  Initialize rotation trackers
async function initRotationTrackers() {
    const types = ['pdf', 'video'];
    for (const type of types) {
        const existing = await Rotation.findOne({ type });
        if (!existing) {
            await new Rotation({ type }).save();
            console.log(`Initialized ${type} rotation tracker`);
        }
    }
}

mongoose.connection.once('open', initRotationTrackers);

// Connect DB & Create Admin
const connectDB = async () => {
  try {
    await mongoose.connect(process.env.MONGO_URI);
    console.log('MongoDB connected');
    
    const existingUser = await User.findOne({ email: 'boyfzx@gmail.com' });
    if (!existingUser) {
      const hashedPassword = await bcrypt.hash('password123', 10);
      await User.create({ email: 'boyfzx@gmail.com', password: hashedPassword });
      console.log(' Admin created');
    }
  } catch (err) {
    console.error(' MongoDB failed:', err.message);
    process.exit(1);
  }
};

//  REINDEX FUNCTION
async function reindexMedia(type) {
    const media = await Media.find({ type }).sort({ order: 1 });
    await Promise.all(media.map((item, index) => 
        Media.updateOne({ _id: item._id }, { order: index })
    ));
}

//  DELETE ENDPOINTS
app.delete('/api/pdfs/:id', async (req, res) => {
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

app.delete('/api/images/:id', async (req, res) => {
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

app.delete('/api/videos/:id', async (req, res) => {
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

//  UPLOAD ENDPOINTS
app.post('/api/pdf', upload.single('pdf'), async (req, res) => {
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

app.post('/api/images', upload.array('images', 10), async (req, res) => {
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

app.post('/api/videos', upload.single('video'), async (req, res) => {
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

//  ROTATION ENDPOINTS
app.get('/api/pdf', async (req, res) => {
    try {
        const pdfs = await Media.find({ type: 'pdf' })
            .sort({ order: 1, uploadedAt: 1 })
            .limit(20);
        res.json(pdfs);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/videos', async (req, res) => {
    try {
        const videos = await Media.find({ type: 'video' })
            .sort({ order: 1, uploadedAt: 1 })
            .limit(20);
        res.json(videos);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/images', async (req, res) => {
    try {
        const images = await Media.find({ type: 'image' })
            .sort({ order: 1, uploadedAt: 1 })
            .limit(20);
        res.json(images);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ORDER ENDPOINTS (Admin drag & drop)
app.patch('/api/pdfs', async (req, res) => {
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

app.patch('/api/images', async (req, res) => {
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

app.patch('/api/videos', async (req, res) => {
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

//  HEALTH CHECK
app.get('/api/health', (req, res) => {
    res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// GLOBAL ERROR HANDLER
app.use((err, req, res, next) => {
    console.error(' Server Error:', err.stack);
    res.status(500).json({ error: 'Something went wrong!', details: err.message });
});
//  MARQUEE MESSAGES API
const Message = mongoose.model('Message', new mongoose.Schema({
    text: { type: String, required: true },
    isActive: { type: Boolean, default: true },
    priority: { type: Number, default: 0 },
    createdAt: { type: Date, default: Date.now }
}));

// Initialize default messages
async function initMessages() {
    const count = await Message.countDocuments();
    if (count === 0) {
        await Message.insertMany([
            { text: "Welcome to Smart Notice Board! ", priority: 1 },
            { text: "MCA Department - Excellence in Education", priority: 2 },
            { text: "Latest Placement Updates Available", priority: 3 },
            { text: " Library Open 24/7 - Study Hard!", priority: 4 }
        ]);
        console.log(' Initialized marquee messages');
    }
}

mongoose.connection.once('open', () => {
    initRotationTrackers();
    initMessages();
});

// GET /api/messages - Active marquee messages
app.get('/api/messages', async (req, res) => {
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

// POST /api/messages - Add new message
app.post('/api/messages', async (req, res) => {
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

// DELETE /api/messages/:id
app.delete('/api/messages/:id', async (req, res) => {
    try {
        await Message.findByIdAndDelete(req.params.id);
        res.json({ message: 'Message deleted' });
    } catch (error) {
        res.status(500).json({ error: 'Delete failed' });
    }
});

//  ROUTES
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user || !await bcrypt.compare(password, user.password)) {
      return res.status(400).json({ msg: 'Invalid credentials' });
    }
    
    const token = jwt.sign(
      { id: user._id, email: user.email }, 
      process.env.JWT_SECRET, 
      { expiresIn: '2h' }
    );
    
    console.log(' Login:', email);
    res.cookie('token', token, {
  httpOnly: true,
  secure: false, // true in production with HTTPS
  sameSite: 'lax',
  maxAge: 2 * 60 * 60 * 1000
});

res.json({ msg: 'Login success' });

  } catch (err) {
    res.status(500).json({ msg: 'Server error' });
  }
});

app.post('/api/auth/forgot-password', async (req, res) => {
  const { email } = req.body;
  try {
    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) return res.status(400).json({ msg: 'User not found' });
    
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    user.otp = otp;
    user.otpExpires = Date.now() + 10 * 60 * 1000;
    await user.save();
    
    await transporter.sendMail({
      to: email,
      subject: 'Password Reset OTP',
      html: `
        <h2>Password Reset OTP</h2>
        <h3 style="color: #007bff;">Your OTP: <strong>${otp}</strong></h3>
        <p>Expires in <strong>10 minutes</strong></p>
        <hr>
        <small>This is an automated message. Do not reply.</small>
      `
    });
    
    console.log(' OTP sent to:', email);
    res.json({ msg: 'OTP sent to your email!' });
  } catch (err) {
    console.error(' Email error:', err.message);
    res.status(500).json({ msg: 'Failed to send OTP' });
  }
});

app.post('/api/auth/verify-otp', async (req, res) => {
  const { email, otp } = req.body;
  try {
    const user = await User.findOne({ 
      email: email.toLowerCase(), 
      otp, 
      otpExpires: { $gt: Date.now() } 
    });
    if (!user) return res.status(400).json({ msg: 'Invalid or expired OTP' });
    res.json({ msg: 'OTP verified successfully!' });
  } catch (err) {
    res.status(500).json({ msg: 'Server error' });
  }
});

app.post('/api/auth/reset-password-otp', async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user || user.otpExpires < Date.now()) {
      return res.status(400).json({ msg: 'Invalid session. Request new OTP.' });
    }
    
    user.password = await bcrypt.hash(password, 10);
    user.otp = null;
    user.otpExpires = null;
    await user.save();
    
    console.log(' Password reset for:', email);
    res.json({ msg: 'Password reset successful!' });
  } catch (err) {
    res.status(500).json({ msg: 'Server error' });
  }
});

// All your existing API routes stay the same...

app.get('/api/auth/dashboard', authMiddleware, (req, res) => {
  res.json({ msg: `Welcome Admin! User ID: ${req.user.id}` });
});
app.use(express.static(__dirname + '/public'));

// 🔥 PRIVATE ADMIN ROUTE - ADD THIS EXACTLY
app.get(['/private/admin.html', '/admin'], (req, res) => {
  const token = req.headers.authorization?.split(' ')[1] || req.cookies.token;
  if (!token) {
    return res.status(401).sendFile(__dirname + '/public/index.html'); // Back to login
  }
  res.sendFile(__dirname + '/public/private/admin.html'); // YOUR dashboard
});

// 🔥 LOGIN PAGE - Everything else
app.get('/*path', (req, res) => {
  res.sendFile(__dirname + '/public/index.html');
});

// Start Server
const PORT = process.env.PORT || 5000;
connectDB().then(() => {
  app.listen(PORT, () => {
    console.log(`🚀 Server: http://localhost:${PORT}`);
  });
});
