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
        console.error('MySQL connection failed:', err);
    } else {
        console.log('Connected to MySQL database.');
    }
});

// Middleware
app.use(cors({
    origin: 'http://localhost:3000',
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
    const privateRoutes = ['/wishlist', '/cart', '/orders', '/profile'];
    const adminRoutes = ['/admin'];

    const isAdminRoute = adminRoutes.some(route => req.path.startsWith(route));
    const isPrivateRoute = privateRoutes.some(route => req.path.startsWith(route));

    if (req.session && req.session.user) {
        res.locals.user = req.session.user;
        if (isAdminRoute && !req.session.user.email.includes("uwezo.co.ke")) {
            return res.status(401).json({ message: 'Unauthorized access. Admins only.' });
        }
        return next();
    } else if (isPrivateRoute || isAdminRoute) {
        return res.status(401).json({ message: 'Please login first.' });
    } else {
        return next();
    }
});

// Routes
app.get('/', (req, res) => {
    res.json({ message: 'Backend is running.' });
});

// Register
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

// Login
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

// Get all products
app.get('/products', (req, res) => {
    dbconn.query('SELECT * FROM products', (err, results) => {
        if (err) return res.status(500).json({ error: err });
        res.status(200).json(results);
    });
});

// Get products by category
app.get('/products/category/:category', (req, res) => {
    const { category } = req.params;
    dbconn.query('SELECT * FROM products WHERE category = ?', [category], (err, results) => {
        if (err) return res.status(500).json({ error: err });
        res.status(200).json(results);
    });
});

// Wishlist
app.get('/wishlist', (req, res) => {
    const userId = req.session.user.id;
    dbconn.query('SELECT * FROM wishlist WHERE user_id = ?', [userId], (err, results) => {
        if (err) return res.status(500).json({ error: err });
        res.status(200).json(results);
    });
});

app.post('/wishlist', (req, res) => {
    const userId = req.session.user.id;
    const { product_id } = req.body;

    dbconn.query('INSERT INTO wishlist (user_id, product_id) VALUES (?, ?)', [userId, product_id], (err) => {
        if (err) return res.status(500).json({ error: err });
        res.status(200).json({ message: 'Product added to wishlist' });
    });
});

app.delete('/wishlist/:product_id', (req, res) => {
    const userId = req.session.user.id;
    const productId = req.params.product_id;

    dbconn.query('DELETE FROM wishlist WHERE user_id = ? AND product_id = ?', [userId, productId], (err) => {
        if (err) return res.status(500).json({ error: err });
        res.status(200).json({ message: 'Product removed from wishlist' });
    });
});

// Admin Routes
app.get('/admin/dashboard', (req, res) => {
    const dashboardData = {};

    dbconn.query('SELECT COUNT(*) AS totalUsers FROM users', (err, usersResult) => {
        if (err) return res.status(500).json({ error: err });
        dashboardData.totalUsers = usersResult[0].totalUsers;

        dbconn.query('SELECT COUNT(*) AS totalProducts FROM products', (err, productsResult) => {
            if (err) return res.status(500).json({ error: err });
            dashboardData.totalProducts = productsResult[0].totalProducts;

            dbconn.query('SELECT COUNT(*) AS totalOrders, SUM(total_amount) AS totalRevenue FROM orders', (err, ordersResult) => {
                if (err) return res.status(500).json({ error: err });
                dashboardData.totalOrders = ordersResult[0].totalOrders || 0;
                dashboardData.totalRevenue = ordersResult[0].totalRevenue || 0;

                dbconn.query(`
                    SELECT p.name, SUM(oi.quantity) AS totalSold
                    FROM order_items oi
                    JOIN products p ON oi.product_id = p.id
                    GROUP BY oi.product_id
                    ORDER BY totalSold DESC
                    LIMIT 5
                `, (err, topProductsResult) => {
                    if (err) return res.status(500).json({ error: err });
                    dashboardData.topProducts = topProductsResult;
                    res.status(200).json(dashboardData);
                });
            });
        });
    });
});

app.get('/admin/users', (req, res) => {
    dbconn.query('SELECT id, name, email FROM users', (err, results) => {
        if (err) return res.status(500).json({ error: err });
        res.status(200).json(results);
    });
});

app.post('/admin/products', (req, res) => {
    const { name, price, image_url } = req.body;
    dbconn.query('INSERT INTO products (name, price, image_url) VALUES (?, ?, ?)', [name, price, image_url], (err) => {
        if (err) return res.status(500).json({ error: err });
        res.status(201).json({ message: 'Product added successfully' });
    });
});

app.put('/admin/products/:id', (req, res) => {
    const { id } = req.params;
    const { name, price, image_url } = req.body;
    dbconn.query('UPDATE products SET name = ?, price = ?, image_url = ? WHERE id = ?', [name, price, image_url, id], (err) => {
        if (err) return res.status(500).json({ error: err });
        res.status(200).json({ message: 'Product updated successfully' });
    });
});

app.delete('/admin/products/:id', (req, res) => {
    const { id } = req.params;
    dbconn.query('DELETE FROM products WHERE id = ?', [id], (err) => {
        if (err) return res.status(500).json({ error: err });
        res.status(200).json({ message: 'Product deleted successfully' });
    });
});

app.get('/admin/orders', (req, res) => {
    dbconn.query(`
        SELECT o.id, o.user_id, u.email, o.total_amount, o.created_at
        FROM orders o
        JOIN users u ON o.user_id = u.id
    `, (err, results) => {
        if (err) return res.status(500).json({ error: err });
        res.status(200).json(results);
    });
});

// Profile
app.get('/profile', (req, res) => {
    const userId = req.session.user.id;
    dbconn.query('SELECT id, name, email FROM users WHERE id = ?', [userId], (err, results) => {
        if (err) return res.status(500).json({ error: err });
        res.status(200).json(results[0]);
    });
});

// Cart & Orders
app.get('/cart', (req, res) => {
    const userId = req.session.user.id;
    dbconn.query('SELECT * FROM cart WHERE user_id = ?', [userId], (err, results) => {
        if (err) return res.status(500).json({ error: err });
        res.status(200).json(results);
    });
});

app.post('/cart', (req, res) => {
    const userId = req.session.user.id;
    const { product_id, quantity } = req.body;
    dbconn.query('INSERT INTO cart (user_id, product_id, quantity) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE quantity = quantity + ?', 
        [userId, product_id, quantity, quantity], 
        (err) => {
            if (err) return res.status(500).json({ error: err });
            res.status(200).json({ message: 'Product added/updated in cart' });
        });
});

app.put('/cart', (req, res) => {
    const userId = req.session.user.id;
    const { product_id, quantity } = req.body;
    dbconn.query('UPDATE cart SET quantity = ? WHERE user_id = ? AND product_id = ?', [quantity, userId, product_id], (err) => {
        if (err) return res.status(500).json({ error: err });
        res.status(200).json({ message: 'Cart item updated' });
    });
});

app.delete('/cart/:product_id', (req, res) => {
    const userId = req.session.user.id;
    const productId = req.params.product_id;
    dbconn.query('DELETE FROM cart WHERE user_id = ? AND product_id = ?', [userId, productId], (err) => {
        if (err) return res.status(500).json({ error: err });
        res.status(200).json({ message: 'Product removed from cart' });
    });
});

app.post('/orders', (req, res) => {
    const userId = req.session.user.id;

    dbconn.query('SELECT c.product_id, c.quantity, p.price FROM cart c JOIN products p ON c.product_id = p.id WHERE c.user_id = ?', 
        [userId], (err, cartItems) => {
            if (err) return res.status(500).json({ error: err });

            if (cartItems.length === 0) {
                return res.status(400).json({ message: 'Cart is empty' });
            }

            const totalAmount = cartItems.reduce((sum, item) => sum + item.price * item.quantity, 0);

            dbconn.query('INSERT INTO orders (user_id, total_amount) VALUES (?, ?)', [userId, totalAmount], (err, result) => {
                if (err) return res.status(500).json({ error: err });

                const orderId = result.insertId;
                const orderItems = cartItems.map(item => [orderId, item.product_id, item.quantity, item.price]);

                dbconn.query('INSERT INTO order_items (order_id, product_id, quantity, price) VALUES ?', [orderItems], (err) => {
                    if (err) return res.status(500).json({ error: err });

                    dbconn.query('DELETE FROM cart WHERE user_id = ?', [userId], (err) => {
                        if (err) return res.status(500).json({ error: err });
                        res.status(201).json({ message: 'Order placed successfully' });
                    });
                });
            });
        });
});

// Start server
const PORT = 5000;
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
