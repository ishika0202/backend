const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-jwt-secret-key';

// Database connection
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Middleware
app.use(cors());
app.use(express.json());

// Database initialization
const initDatabase = async () => {
    try {
        // Create users table
        await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        name VARCHAR(60) NOT NULL,
        email VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        address TEXT,
        role VARCHAR(20) DEFAULT 'user' CHECK (role IN ('admin', 'user', 'store_owner')),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

        // Create stores table
        await pool.query(`
      CREATE TABLE IF NOT EXISTS stores (
        id SERIAL PRIMARY KEY,
        name VARCHAR(60) NOT NULL,
        email VARCHAR(255) UNIQUE NOT NULL,
        address TEXT,
        owner_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

        // Create ratings table
        await pool.query(`
      CREATE TABLE IF NOT EXISTS ratings (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        store_id INTEGER REFERENCES stores(id) ON DELETE CASCADE,
        rating INTEGER CHECK (rating >= 1 AND rating <= 5),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(user_id, store_id)
      )
    `);

        // Create default admin user
        const adminExists = await pool.query('SELECT id FROM users WHERE email = $1', ['admin@admin.com']);
        if (adminExists.rows.length === 0) {
            const hashedPassword = await bcrypt.hash('Admin123!', 10);
            await pool.query(
                'INSERT INTO users (name, email, password, address, role) VALUES ($1, $2, $3, $4, $5)',
                ['System Administrator', 'admin@admin.com', hashedPassword, 'System Address', 'admin']
            );
        }

        console.log('Database initialized successfully');
    } catch (error) {
        console.error('Database initialization error:', error);
    }
};

// Authentication middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Access token required' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid token' });
        }
        req.user = user;
        next();
    });
};

// Role-based authorization middleware
const authorizeRole = (roles) => {
    return (req, res, next) => {
        if (!roles.includes(req.user.role)) {
            return res.status(403).json({ error: 'Insufficient permissions' });
        }
        next();
    };
};

// Validation middleware
const validateUser = (req, res, next) => {
    const { name, email, password, address } = req.body;
    const errors = [];

    if (!name || name.length < 20 || name.length > 60) {
        errors.push('Name must be between 20 and 60 characters');
    }

    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        errors.push('Valid email is required');
    }

    if (!password || password.length < 8 || password.length > 16 ||
        !/[A-Z]/.test(password) || !/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
        errors.push('Password must be 8-16 characters with at least one uppercase letter and one special character');
    }

    if (address && address.length > 400) {
        errors.push('Address must not exceed 400 characters');
    }

    if (errors.length > 0) {
        return res.status(400).json({ errors });
    }

    next();
};

// Routes

app.get('/', (req, res) => {
    res.json({ message: 'InternRock backend service is running.' });
});

// Auth Routes
app.post('/api/auth/register', validateUser, async (req, res) => {
    try {
        const { name, email, password, address } = req.body;

        // Check if user exists
        const userExists = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
        if (userExists.rows.length > 0) {
            return res.status(400).json({ error: 'User already exists' });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create user
        const result = await pool.query(
            'INSERT INTO users (name, email, password, address, role) VALUES ($1, $2, $3, $4, $5) RETURNING id, name, email, address, role',
            [name, email, hashedPassword, address, 'user']
        );

        const user = result.rows[0];
        const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, { expiresIn: '24h' });

        res.status(201).json({
            message: 'User created successfully',
            token,
            user: { id: user.id, name: user.name, email: user.email, address: user.address, role: user.role }
        });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        // Find user
        const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        if (result.rows.length === 0) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const user = result.rows[0];

        // Check password
        const isValidPassword = await bcrypt.compare(password, user.password);
        if (!isValidPassword) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Generate token
        const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, { expiresIn: '24h' });

        res.json({
            message: 'Login successful',
            token,
            user: { id: user.id, name: user.name, email: user.email, address: user.address, role: user.role }
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// User Routes
app.get('/api/users/profile', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT id, name, email, address, role FROM users WHERE id = $1',
            [req.user.id]
        );
        res.json(result.rows[0]);
    } catch (error) {
        console.error('Profile fetch error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.put('/api/users/password', authenticateToken, async (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;

        // Validate new password
        if (!newPassword || newPassword.length < 8 || newPassword.length > 16 ||
            !/[A-Z]/.test(newPassword) || !/[!@#$%^&*(),.?":{}|<>]/.test(newPassword)) {
            return res.status(400).json({
                error: 'Password must be 8-16 characters with at least one uppercase letter and one special character'
            });
        }

        // Get current user
        const userResult = await pool.query('SELECT password FROM users WHERE id = $1', [req.user.id]);
        const user = userResult.rows[0];

        // Verify current password
        const isValidPassword = await bcrypt.compare(currentPassword, user.password);
        if (!isValidPassword) {
            return res.status(400).json({ error: 'Current password is incorrect' });
        }

        // Update password
        const hashedNewPassword = await bcrypt.hash(newPassword, 10);
        await pool.query('UPDATE users SET password = $1 WHERE id = $2', [hashedNewPassword, req.user.id]);

        res.json({ message: 'Password updated successfully' });
    } catch (error) {
        console.error('Password update error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Admin Routes
app.get('/api/admin/dashboard', authenticateToken, authorizeRole(['admin']), async (req, res) => {
    try {
        const usersCount = await pool.query('SELECT COUNT(*) FROM users');
        const storesCount = await pool.query('SELECT COUNT(*) FROM stores');
        const ratingsCount = await pool.query('SELECT COUNT(*) FROM ratings');

        res.json({
            totalUsers: parseInt(usersCount.rows[0].count),
            totalStores: parseInt(storesCount.rows[0].count),
            totalRatings: parseInt(ratingsCount.rows[0].count)
        });
    } catch (error) {
        console.error('Dashboard error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.get('/api/admin/users', authenticateToken, authorizeRole(['admin']), async (req, res) => {
    try {
        const { sortBy = 'name', sortOrder = 'asc', search = '' } = req.query;

        let query = `
      SELECT u.id, u.name, u.email, u.address, u.role, 
             COALESCE(AVG(r.rating), 0) as rating
      FROM users u
      LEFT JOIN stores s ON u.id = s.owner_id
      LEFT JOIN ratings r ON s.id = r.store_id
      WHERE u.name ILIKE $1 OR u.email ILIKE $1 OR u.address ILIKE $1
      GROUP BY u.id, u.name, u.email, u.address, u.role
      ORDER BY ${sortBy} ${sortOrder.toUpperCase()}
    `;

        const result = await pool.query(query, [`%${search}%`]);
        res.json(result.rows);
    } catch (error) {
        console.error('Users fetch error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/api/admin/users', authenticateToken, authorizeRole(['admin']), validateUser, async (req, res) => {
    try {
        const { name, email, password, address, role = 'user' } = req.body;

        // Check if user exists
        const userExists = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
        if (userExists.rows.length > 0) {
            return res.status(400).json({ error: 'User already exists' });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create user
        const result = await pool.query(
            'INSERT INTO users (name, email, password, address, role) VALUES ($1, $2, $3, $4, $5) RETURNING id, name, email, address, role',
            [name, email, hashedPassword, address, role]
        );

        res.status(201).json({
            message: 'User created successfully',
            user: result.rows[0]
        });
    } catch (error) {
        console.error('User creation error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.get('/api/admin/stores', authenticateToken, authorizeRole(['admin']), async (req, res) => {
    try {
        const { sortBy = 'name', sortOrder = 'asc', search = '' } = req.query;

        let query = `
      SELECT s.id, s.name, s.email, s.address, COALESCE(AVG(r.rating), 0) as rating
      FROM stores s
      LEFT JOIN ratings r ON s.id = r.store_id
      WHERE s.name ILIKE $1 OR s.email ILIKE $1 OR s.address ILIKE $1
      GROUP BY s.id, s.name, s.email, s.address
      ORDER BY ${sortBy} ${sortOrder.toUpperCase()}
    `;

        const result = await pool.query(query, [`%${search}%`]);
        res.json(result.rows);
    } catch (error) {
        console.error('Stores fetch error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/api/admin/stores', authenticateToken, authorizeRole(['admin']), async (req, res) => {
    try {
        const { name, email, address, ownerEmail, ownerPassword } = req.body;

        // Validate store name
        if (!name || name.length < 20 || name.length > 60) {
            return res.status(400).json({ error: 'Store name must be between 20 and 60 characters' });
        }

        // Validate email
        if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
            return res.status(400).json({ error: 'Valid email is required' });
        }

        // Check if store exists
        const storeExists = await pool.query('SELECT id FROM stores WHERE email = $1', [email]);
        if (storeExists.rows.length > 0) {
            return res.status(400).json({ error: 'Store already exists' });
        }

        // Create store owner if provided
        let ownerId = null;
        if (ownerEmail && ownerPassword) {
            // Validate owner password
            if (ownerPassword.length < 8 || ownerPassword.length > 16 ||
                !/[A-Z]/.test(ownerPassword) || !/[!@#$%^&*(),.?":{}|<>]/.test(ownerPassword)) {
                return res.status(400).json({
                    error: 'Owner password must be 8-16 characters with at least one uppercase letter and one special character'
                });
            }

            const hashedPassword = await bcrypt.hash(ownerPassword, 10);
            const ownerResult = await pool.query(
                'INSERT INTO users (name, email, password, address, role) VALUES ($1, $2, $3, $4, $5) RETURNING id',
                [name, ownerEmail, hashedPassword, address, 'store_owner']
            );
            ownerId = ownerResult.rows[0].id;
        }

        // Create store
        const result = await pool.query(
            'INSERT INTO stores (name, email, address, owner_id) VALUES ($1, $2, $3, $4) RETURNING *',
            [name, email, address, ownerId]
        );

        res.status(201).json({
            message: 'Store created successfully',
            store: result.rows[0]
        });
    } catch (error) {
        console.error('Store creation error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Store Routes
app.get('/api/stores', authenticateToken, async (req, res) => {
    try {
        const { search = '' } = req.query;

        let query = `
      SELECT s.id, s.name, s.address, COALESCE(AVG(r.rating), 0) as rating,
             ur.rating as user_rating
      FROM stores s
      LEFT JOIN ratings r ON s.id = r.store_id
      LEFT JOIN ratings ur ON s.id = ur.store_id AND ur.user_id = $2
      WHERE s.name ILIKE $1 OR s.address ILIKE $1
      GROUP BY s.id, s.name, s.address, ur.rating
      ORDER BY s.name
    `;

        const result = await pool.query(query, [`%${search}%`, req.user.id]);
        res.json(result.rows);
    } catch (error) {
        console.error('Stores fetch error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.get('/api/store-owner/dashboard', authenticateToken, authorizeRole(['store_owner']), async (req, res) => {
    try {
        // Get store owned by this user
        const storeResult = await pool.query('SELECT id FROM stores WHERE owner_id = $1', [req.user.id]);
        if (storeResult.rows.length === 0) {
            return res.status(404).json({ error: 'No store found for this owner' });
        }

        const storeId = storeResult.rows[0].id;

        // Get average rating
        const avgRatingResult = await pool.query(
            'SELECT COALESCE(AVG(rating), 0) as average_rating FROM ratings WHERE store_id = $1',
            [storeId]
        );

        // Get users who rated this store
        const ratingsResult = await pool.query(`
      SELECT u.name, u.email, r.rating, r.created_at
      FROM ratings r
      JOIN users u ON r.user_id = u.id
      WHERE r.store_id = $1
      ORDER BY r.created_at DESC
    `, [storeId]);

        res.json({
            averageRating: parseFloat(avgRatingResult.rows[0].average_rating),
            ratings: ratingsResult.rows
        });
    } catch (error) {
        console.error('Store owner dashboard error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});
app.post('/api/ratings', authenticateToken, authorizeRole(['user']), async (req, res) => {
    try {
        const { storeId, rating } = req.body;

        if (!rating || rating < 1 || rating > 5) {
            return res.status(400).json({ error: 'Rating must be between 1 and 5' });
        }

        // Check if rating exists, update or insert
        const existingRating = await pool.query(
            'SELECT id FROM ratings WHERE user_id = $1 AND store_id = $2',
            [req.user.id, storeId]
        );

        if (existingRating.rows.length > 0) {
            await pool.query(
                'UPDATE ratings SET rating = $1 WHERE user_id = $2 AND store_id = $3',
                [rating, req.user.id, storeId]
            );
            res.json({ message: 'Rating updated successfully' });
        } else {
            await pool.query(
                'INSERT INTO ratings (user_id, store_id, rating) VALUES ($1, $2, $3)',
                [req.user.id, storeId, rating]
            );
            res.json({ message: 'Rating submitted successfully' });
        }
    } catch (error) {
        console.error('Rating submission error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});
// Initialize database and start server
initDatabase().then(() => {
    app.listen(PORT, () => {
        console.log(`Server running on port ${PORT}`);
    });
});

module.exports = app;