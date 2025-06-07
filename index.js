const express = require('express');
const mysql = require('mysql');
const bcrypt = require('bcrypt');
const session = require('express-session');
const cors = require('cors');
const path = require('path');

const app = express();

// Database connection
const dbconn = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '',
    database: 'ecommercedb'
});

dbconn.connect((err) => {
    if (err) {
        console.error('MySQL connection failed: ', err);
    } else {
        console.log('Connected to MySQL database.');
    }
});

// Middleware
app.use(cors({
    origin: 'http://localhost:3000', // React dev server
    credentials: true
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

app.use(session({
    secret: 'your encryptionkey',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false }
}));

// Auth Middleware
app.use((req, res, next) => {
    const privateRoutes = ['/cart'];
    const adminRoutes = ['/update', '/admprofile'];

    if (req.session && req.session.user) {
        res.locals.user = req.session.user;

        if (!req.session.user.email.includes("uwezo.co.ke") && adminRoutes.includes(req.path)) {
            return res.status(401).json({ message: 'Unauthorized access. Admins only.' });
        } else {
            return next();
        }
    } else if (privateRoutes.includes(req.path) || adminRoutes.includes(req.path)) {
        return res.status(401).json({ message: 'Please login first.' });
    } else {
        return next();
    }
});

// Routes

app.get('/', (req, res) => {
    res.json({ message: 'Backend is running.' });
});

// Register route
app.post('/register', async (req, res) => {
    const { email, password, name } = req.body;

    const hashedPassword = await bcrypt.hash(password, 10);
    dbconn.query('INSERT INTO users (name, email, password) VALUES (?, ?, ?)', 
        [name, email, hashedPassword], 
        (err, result) => {
            if (err) return res.status(500).json({ error: err });
            res.status(200).json({ message: 'User registered successfully.' });
        }
    );
});

// Login route
app.post('/login', (req, res) => {
    const { email, password } = req.body;

    dbconn.query('SELECT * FROM users WHERE email = ?', [email], (err, results) => {
        if (err) return res.status(500).json({ error: err });
        if (results.length === 0) return res.status(401).json({ message: 'User not found' });

        const user = results[0];

        bcrypt.compare(password, user.password, (err, isMatch) => {
            if (err) return res.status(500).json({ error: err });
            if (!isMatch) return res.status(401).json({ message: 'Incorrect password' });

            req.session.user = user;
            res.status(200).json({ message: 'Login successful', user });
        });
    });
});

// Logout
app.post('/logout', (req, res) => {
    req.session.destroy(() => {
        res.clearCookie('connect.sid');
        res.status(200).json({ message: 'Logged out successfully' });
    });
});

// Start server
const PORT = 5000;
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
