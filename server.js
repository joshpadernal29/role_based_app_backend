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
    origin: ['http://127.0.0.1:5000','http://localhost:5500']
}));

// middleware to parse json
app.use(express.json());

// in memory db (replace db later)
let users = [
    // pre hashed
    {id:1,username:'admin',password:'$2a$10$...', role: 'admin'}, 
    {id: 2, username: 'alice', password: '$2a$10$...', role: 'user'}
];


// pre hashed passwords demo
if (!users[0].password.includes('$2a$')) {
    users[0].password = bcrypt.hashSync('admin123',10);
    users[1].password = bcrypt.hashSync('user123',10);
}

// Auth routes

// POST/api/register
app.post('api/register', async (req,res) => {
    const {username,password,role = 'user'} = req.body;

    // check username and password
    if (!username || !password) {
        return res.status(400).json({error: 'username and password is required!'});
    }

    // check if the user exists
    const exist = users.find(user => user.username === username);
    if (exist){
        return res.status(409).json({error: 'user already exists'});
    }

    // hash user password for every new user
    const hashed_password = await bcrypt.hash(password,10);
    const newUser = {
        id: users.length + 1,
        username,
        password:hashed_password,
        role 
    };
    // add user to storage
    users.push(newUser);
    res.status(201).json({message: 'user registered' + username, role});
});
