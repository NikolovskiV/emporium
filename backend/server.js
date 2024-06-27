const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const bodyParser = require('body-parser');
const multer = require('multer');
const path = require('path');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;
const MONGO_URI = process.env.MONGO_URI;
const JWT_SECRET = process.env.JWT_SECRET;

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Connect to MongoDB
mongoose.connect(MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
})
    .then(() => console.log('MongoDB connected'))
    .catch(err => console.log(err));

// Define User schema and model
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    avatar: { type: String },
});

const User = mongoose.model('User', userSchema);

// Multer setup for file upload
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, './uploads'); // Directory where uploaded files will be stored
    },
    filename: function (req, file, cb) {
        const ext = path.extname(file.originalname);
        cb(null, `${file.fieldname}-${Date.now()}${ext}`);
    }
});

const upload = multer({ storage });

// Middleware to verify JWT
const verifyToken = (req, res, next) => {
    const token = req.headers['authorization'];
    if (!token) return res.status(401).json({ message: 'Access denied' });

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (err) {
        res.status(400).json({ message: 'Invalid token' });
    }
};

// // Register route with file upload
// app.post('/register', upload.single('avatar'), async (req, res) => {
//     const { username, password } = req.body;
//     const avatar = req.file ? req.file.path.replace('\\', '/') : null; // Handle path separators for Windows

//     try {
//         const hashedPassword = await bcrypt.hash(password, 10);
//         const user = new User({ username, password: hashedPassword, avatar });

//         await user.save();

//         const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '1h' });
//         res.json({ token, avatar: user.avatar });
//     } catch (err) {
//         console.error(err);
//         res.status(400).json({ error: err.message });
//     }
// });

// Login route
// Register route with file upload
app.post('/register', upload.single('avatar'), async (req, res) => {
    const { username, password } = req.body;
    const avatar = req.file ? req.file.path.replace(/\\/g, '/') : null; // Ensure path separators are correct

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({ username, password: hashedPassword, avatar });

        await user.save();

        const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '1h' });
        res.json({ token, avatar: user.avatar }); // Send back the avatar path to the client
    } catch (err) {
        console.error(err);
        res.status(400).json({ error: err.message });
    }
});


// Login route
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    try {
        const user = await User.findOne({ username });
        if (!user) return res.status(400).json({ message: 'Invalid username or password' });

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).json({ message: 'Invalid username or password' });

        const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '1h' });
        res.json({ token, avatar: user.avatar });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server error' });
    }
});



// Serve static files from the 'uploads' directory
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));


// Start the server
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
