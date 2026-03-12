// initialized libraries
const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");

// app config
const app = express();
const PORT = 3000;
const SECRET_KEY = 'verySecretKey';


// enable cors for frontend (change url based on what you want to use) 
app.use(cors({
    origin: ['http://127.0.0.1:5000', 'http://localhost:5500']
}));

// middleware to parse json
app.use(express.json());

// in memory db (replace db later)
let users = [
    // pre hashed
    { id: 1, username: 'admin', password: '$2a$10$...', role: 'admin' },
    { id: 2, username: 'alice', password: '$2a$10$...', role: 'user' }
];


// pre hashed passwords demo
if (!users[0].password.includes('$2a$')) {
    users[0].password = bcrypt.hashSync('admin123', 10);
    users[1].password = bcrypt.hashSync('user123', 10);
}

// Auth routes

// POST/api/register
app.post('api/register', async (req, res) => {
    const { username, password, role = 'user' } = req.body;

    // check username and password
    if (!username || !password) {
        return res.status(400).json({ error: 'username and password is required!' });
    }

    // check if the user exists
    const exist = users.find(user => user.username === username);
    if (exist) {
        return res.status(409).json({ error: 'user already exists' });
    }

    // hash user password for every new user
    const hashed_password = await bcrypt.hash(password, 10);
    const newUser = {
        id: users.length + 1,
        username,
        password: hashed_password,
        role
    };
    // add user to storage
    users.push(newUser);
    res.status(201).json({ message: 'user registered' + username, role });
});

// api/ogin route (document this)
app.post('api/login', async (req, res) => {
    const { username, password } = req.body;

    const user = users.find(user => user.username === username);
    if (!user || !await bcrypt.compare(password, user.password)) {
        return res.status(401).json({ error: 'Invalid credentials' });
    }

    // generate JWT token which will expire in 30 seconds
    const token = jwt.sign({
        id: user.id,
        username: user.username,
        role: user.role,
    }, SECRET_KEY, { expiresIn: '30s' });

    res.json({ token, user: { username: user.username, role: user.role } });
});


// protected route : get user profile
app.get('/api/profile', authenticateToken, (req, res) => {
    res.json({ user: req.user });
});

// role-based protected route : Admin 
app.get('/api/admin/dashboard', authenticateToken, authorizeRole('admin'), (req, res) => {
    res.json({ message: 'Welcome to the Admin Dashboard!', data: 'secret_admin_info' });
});

// Public route: Guest Route
app.get('/api/content/guest', (req, res) => {
    res.json({ message: 'Public content for all Guests' });
});

