require('dotenv').config();
const express = require('express');
const mysql = require('mysql');
const bcrypt = require('bcrypt');
const session = require('express-session');
const MySQLStore = require('express-mysql-session')(session);
const cors = require('cors');
const { body, validationResult } = require('express-validator');
const csurf = require('csurf');

const app = express();

// Database connection pool
const pool = mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'ecoommercedb',
    connectionLimit: 10
});

// Session store
const sessionStore = new MySQLStore({}, pool);

// Middleware
app.use(cors({
    origin: process.env.FRONTEND_URL || 'http://localhost:3000',
    credentials: true
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

app.use(session({
    secret: process.env.SESSION_SECRET || 'your_encryptionkey',
    store: sessionStore,
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: process.env.NODE_ENV === 'production',
        maxAge: 24 * 60 * 60 * 1000 // 1 day
    }
}));

app.use(csurf());

// Auth Middleware
app.use((req, res, next) => {
    const privateRoutes = ['/wishlist', '/cart', '/orders', '/profile'];
    const adminRoutes = ['/admin'];

    const isAdminRoute = adminRoutes.some(route => req.path.startsWith(route));
    const isPrivateRoute = privateRoutes.some(route => req.path.startsWith(route));

    if (req.session && req.session.user) {
        res.locals.user = req.session.user;
        if (isAdminRoute && !req.session.user.is_admin) {
            return res.status(403).json({ message: 'Unauthorized access. Admins only.' });
        }
        return next();
    } else if (isPrivateRoute || isAdminRoute) {
        return res.status(401).json({ message: 'Please login first.' });
    }
    next();
});

// CSRF Token Route
app.get('/csrf-token', (req, res) => {
    res.json({ csrfToken: req.csrfToken() });
});

// Error Handling Middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    if (err.code === 'EBADCSRFTOKEN') {
        return res.status(403).json({ message: 'Invalid CSRF token' });
    }
    res.status(500).json({ message: 'Something went wrong!' });
});

// Routes
app.get('/', (req, res) => {
    res.json({ message: 'Backend is running.' });
});

// Register
app.post('/register', [
    body('email').isEmail().normalizeEmail(),
    body('password').isLength({ min: 6 }),
    body('name').notEmpty().trim()
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { email, password, name } = req.body;

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        pool.query('SELECT * FROM users WHERE email = ?', [email], (err, results) => {
            if (err) {
                console.error(err);
                return res.status(500).json({ message: 'Database error' });
            }
            if (results.length > 0) return res.status(400).json({ message: 'Email already exists' });

            pool.query('INSERT INTO users (name, email, password, is_admin) VALUES (?, ?, ?, ?)',
                [name, email, hashedPassword, false], (err) => {
                    if (err) {
                        console.error(err);
                        return res.status(500).json({ message: 'Failed to register user' });
                    }
                    res.status(201).json({ message: 'User registered successfully' });
                });
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error' });
    }
});

// Login
app.post('/login', [
    body('email').isEmail().normalizeEmail(),
    body('password').notEmpty()
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { email, password } = req.body;

    pool.query('SELECT * FROM users WHERE email = ?', [email], (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ message: 'Database error' });
        }
        if (results.length === 0) return res.status(401).json({ message: 'User not found' });

        const user = results[0];
        bcrypt.compare(password, user.password, (err, isMatch) => {
            if (err) {
                console.error(err);
                return res.status(500).json({ message: 'Server error' });
            }
            if (!isMatch) return res.status(401).json({ message: 'Incorrect password' });

            req.session.user = user;
            res.status(200).json({ message: 'Login successful', user: { id: user.id, name: user.name, email: user.email, is_admin: user.is_admin } });
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
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const offset = (page - 1) * limit;

    pool.query('SELECT * FROM products LIMIT ? OFFSET ?', [limit, offset], (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ message: 'Database error' });
        }
        res.status(200).json(results);
    });
});

// Get products by category
app.get('/products/category/:category', (req, res) => {
    const { category } = req.params;
    if (!category.match(/^[a-zA-Z0-9\s-]+$/)) {
        return res.status(400).json({ message: 'Invalid category' });
    }

    pool.query('SELECT * FROM products WHERE category = ?', [category], (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ message: 'Database error' });
        }
        res.status(200).json(results);
    });
});

// Wishlist
app.get('/wishlist', (req, res) => {
    const userId = req.session.user.id;
    pool.query('SELECT * FROM wishlist WHERE user_id = ?', [userId], (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ message: 'Database error' });
        }
        res.status(200).json(results);
    });
});

app.post('/wishlist', [
    body('product_id').isInt()
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const userId = req.session.user.id;
    const { product_id } = req.body;

    pool.query('INSERT INTO wishlist (user_id, product_id) VALUES (?, ?)', [userId, product_id], (err) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ message: 'Database error' });
        }
        res.status(200).json({ message: 'Product added to wishlist' });
    });
});

app.delete('/wishlist/:product_id', (req, res) => {
    const userId = req.session.user.id;
    const productId = parseInt(req.params.product_id);
    if (isNaN(productId)) return res.status(400).json({ message: 'Invalid product ID' });

    pool.query('DELETE FROM wishlist WHERE user_id = ? AND product_id = ?', [userId, productId], (err) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ message: 'Database error' });
        }
        res.status(200).json({ message: 'Product removed from wishlist' });
    });
});

// Admin Routes
app.get('/admin/dashboard', (req, res) => {
    const dashboardData = {};

    pool.query('SELECT COUNT(*) AS totalUsers FROM users', (err, usersResult) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ message: 'Database error' });
        }
        dashboardData.totalUsers = usersResult[0].totalUsers;

        pool.query('SELECT COUNT(*) AS totalProducts FROM products', (err, productsResult) => {
            if (err) {
                console.error(err);
                return res.status(500).json({ message: 'Database error' });
            }
            dashboardData.totalProducts = productsResult[0].totalProducts;

            pool.query('SELECT COUNT(*) AS totalOrders, SUM(total_amount) AS totalRevenue FROM orders', (err, ordersResult) => {
                if (err) {
                    console.error(err);
                    return res.status(500).json({ message: 'Database error' });
                }
                dashboardData.totalOrders = ordersResult[0].totalOrders || 0;
                dashboardData.totalRevenue = ordersResult[0].totalRevenue || 0;

                pool.query(`
                    SELECT p.name, SUM(oi.quantity) AS totalSold
                    FROM order_items oi
                    JOIN products p ON oi.product_id = p.id
                    GROUP BY oi.product_id
                    ORDER BY totalSold DESC
                    LIMIT 5
                `, (err, topProductsResult) => {
                    if (err) {
                        console.error(err);
                        return res.status(500).json({ message: 'Database error' });
                    }
                    dashboardData.topProducts = topProductsResult;
                    res.status(200).json(dashboardData);
                });
            });
        });
    });
});

app.get('/admin/users', (req, res) => {
    pool.query('SELECT id, name, email, is_admin FROM users', (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ message: 'Database error' });
        }
        res.status(200).json(results);
    });
});

app.post('/admin/products', [
    body('name').notEmpty().trim(),
    body('price').isFloat({ min: 0 }),
    body('image_url').optional().isURL()
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { name, price, image_url } = req.body;
    pool.query('INSERT INTO products (name, price, image_url) VALUES (?, ?, ?)', [name, price, image_url || null], (err) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ message: 'Database error' });
        }
        res.status(201).json({ message: 'Product added successfully' });
    });
});

app.put('/admin/products/:id', [
    body('name').notEmpty().trim(),
    body('price').isFloat({ min: 0 }),
    body('image_url').optional().isURL()
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { id } = req.params;
    const { name, price, image_url } = req.body;
    pool.query('UPDATE products SET name = ?, price = ?, image_url = ? WHERE id = ?', [name, price, image_url || null, id], (err) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ message: 'Database error' });
        }
        res.status(200).json({ message: 'Product updated successfully' });
    });
});

app.delete('/admin/products/:id', (req, res) => {
    const { id } = req.params;
    pool.query('DELETE FROM products WHERE id = ?', [id], (err) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ message: 'Database error' });
        }
        res.status(200).json({ message: 'Product deleted successfully' });
    });
});

app.get('/admin/orders', (req, res) => {
    pool.query(`
        SELECT o.id, o.user_id, u.email, o.total_amount, o.created_at
        FROM orders o
        JOIN users u ON o.user_id = u.id
    `, (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ message: 'Database error' });
        }
        res.status(200).json(results);
    });
});

// Profile
app.get('/profile', (req, res) => {
    const userId = req.session.user.id;
    pool.query('SELECT id, name, email, is_admin FROM users WHERE id = ?', [userId], (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ message: 'Database error' });
        }
        if (results.length === 0) return res.status(404).json({ message: 'User not found' });
        res.status(200).json(results[0]);
    });
});

// Cart & Orders
app.get('/cart', (req, res) => {
    const userId = req.session.user.id;
    pool.query('SELECT * FROM cart WHERE user_id = ?', [userId], (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ message: 'Database error' });
        }
        res.status(200).json(results);
    });
});

app.post('/cart', [
    body('product_id').isInt(),
    body('quantity').isInt({ min: 1 })
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const userId = req.session.user.id;
    const { product_id, quantity } = req.body;
    pool.query('INSERT INTO cart (user_id, product_id, quantity) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE quantity = quantity + ?', 
        [userId, product_id, quantity, quantity], (err) => {
            if (err) {
                console.error(err);
                return res.status(500).json({ message: 'Database error' });
            }
            res.status(200).json({ message: 'Product added/updated in cart' });
        });
});

app.put('/cart', [
    body('product_id').isInt(),
    body('quantity').isInt({ min: 1 })
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const userId = req.session.user.id;
    const { product_id, quantity } = req.body;
    pool.query('UPDATE cart SET quantity = ? WHERE user_id = ? AND product_id = ?', [quantity, userId, product_id], (err) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ message: 'Database error' });
        }
        res.status(200).json({ message: 'Cart item updated' });
    });
});

app.delete('/cart/:product_id', (req, res) => {
    const userId = req.session.user.id;
    const productId = parseInt(req.params.product_id);
    if (isNaN(productId)) return res.status(400).json({ message: 'Invalid product ID' });

    pool.query('DELETE FROM cart WHERE user_id = ? AND product_id = ?', [userId, productId], (err) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ message: 'Database error' });
        }
        res.status(200).json({ message: 'Product removed from cart' });
    });
});

app.post('/orders', (req, res) => {
    const userId = req.session.user.id;

    pool.query('SELECT c.product_id, c.quantity, p.price FROM cart c JOIN products p ON c.product_id = p.id WHERE c.user_id = ?', 
        [userId], (err, cartItems) => {
            if (err) {
                console.error(err);
                return res.status(500).json({ message: 'Database error' });
            }

            if (cartItems.length === 0) {
                return res.status(400).json({ message: 'Cart is empty' });
            }

            const totalAmount = cartItems.reduce((sum, item) => sum + item.price * item.quantity, 0);

            pool.query('INSERT INTO orders (user_id, total_amount) VALUES (?, ?)', [userId, totalAmount], (err, result) => {
                if (err) {
                    console.error(err);
                    return res.status(500).json({ message: 'Database error' });
                }

                const orderId = result.insertId;
                const orderItems = cartItems.map(item => [orderId, item.product_id, item.quantity, item.price]);

                pool.query('INSERT INTO order_items (order_id, product_id, quantity, price) VALUES ?', [orderItems], (err) => {
                    if (err) {
                        console.error(err);
                        return res.status(500).json({ message: 'Database error' });
                    }

                    pool.query('DELETE FROM cart WHERE user_id = ?', [userId], (err) => {
                        if (err) {
                            console.error(err);
                            return res.status(500).json({ message: 'Database error' });
                        }
                        res.status(201).json({ message: 'Order placed successfully' });
                    });
                });
            });
        });
});

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});