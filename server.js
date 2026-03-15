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
    origin: [
        'http://127.0.0.1:5500',
        'http://localhost:5500',
        'http://127.0.0.1:5000',
        'http://localhost:5000'
    ],
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization'] // Crucial for Part 4 testing
}));

// middleware to parse json
app.use(express.json());

// in memory db (replace db later)
let users = [
    // pre hashed      
    {
        id: 1,
        username: 'admin',
        password: 'admin123',
        role: 'admin',
        Fname: 'admin',    // Added
        Lname: '123',     // Added
        email: 'admin@test.com' // Added
    },
    {
        id: 2,
        username: 'alice',
        password: 'user123',
        role: 'user',
        Fname: 'Alice',     // Added
        Lname: 'Smith',     // Added
        email: 'alice@example.com' // Added
    }
];


// pre hashed passwords demo
if (!users[0].password.includes('$2a$')) {
    // test password hashing
    users[0].password = bcrypt.hashSync(users[0].password, 10);
    users[1].password = bcrypt.hashSync(users[1].password, 10);
}

// Auth routes

// POST/api/register - to be added
app.post('/api/register', async (req, res) => {
    const { username, password, Fname, Lname, email, role = 'user' } = req.body;

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
        role,
        Fname,  // Save First Name
        Lname,  // Save Last Name
        email   // Save Email
    };
    // add user to storage
    users.push(newUser);
    res.status(201).json({
        message: 'User registered: ' + username,
        email: newUser.email,
        Fname: newUser.Fname
    });
});

// api/ogin route (document this)
app.post('/api/login', async (req, res) => {
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

    // added email,fname,lname from the frontend - document this
    res.json({
        token,
        user: {
            username: user.username,
            role: user.role,
            Fname: user.Fname,
            Lname: user.Lname,
            email: user.email
        }
    });
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


// Token Authentication
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // bearer token

    // check if there is an access token
    if (!token) {
        return res.status(401).json({ error: 'Access token required!' });
    }

    // verify token 
    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) return res.status(403).json({ error: 'Invalid or expired token!' });
        req.user = user;
        next();
    });
}

// role authorization
function authorizeRole(role) {
    return (req, res, next) => {
        if (req.user.role !== role) {
            return res.status(403).json({ error: 'Access denied!: insufficient permissions!' });
        }
        next();
    };
}

// start server
app.listen(PORT, () => {
    console.log(`Backend running at http://localhost:${PORT}`);
    console.log("Try Logging in With: ");
    console.log("Admin: username: admin, password: admin123");
    console.log("User: username: alice, password: user123");
});
