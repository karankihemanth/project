const express = require('express');
const bodyParser = require('body-parser');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const path = require('path');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const app = express();
const port = 3000;

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: 'Hemanth',
    database: 'registration'
});

db.connect((err) => {
    if (err) {
        throw err;
    } else {
        console.log("MySQL connected...");
    }
});

// Configure Nodemailer
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: 'lovelong4362684@gmail.com',
        pass: 'Hemanth@25'
    }
});

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.use(express.static('public'));

// Register route
app.post('/register', (req, res) => {
    const { name, email, pass, confirmPass } = req.body;

    if (!name || !email || !pass || !confirmPass) {
        return res.status(400).send('All fields are required');
    }
    const checkEmailSql = 'SELECT * FROM userinfo WHERE mail = ?';
    db.query(checkEmailSql, [email], (err, results) => {
        if (err) throw err;

        if (results.length > 0) {
            return res.status(400).send('Email already exists');
        }
        if (pass !== confirmPass) {
            return res.status(400).send('Passwords do not match');
        }
        bcrypt.hash(pass, 10, (err, hash) => {
            if (err) throw err;
            const sql = 'INSERT INTO userinfo (name, mail, pass) VALUES (?, ?, ?)';
            db.query(sql, [name, email, hash], (err, result) => {
                if (err) throw err;
                res.send('User registered...');
            });
        });
    });
});

// Login route
app.post('/login', (req, res) => {
    const { email, pass } = req.body;
    if (!email || !pass) {
        return res.status(400).send('All fields are required');
    }
    const sql = 'SELECT * FROM userinfo WHERE mail = ?';
    db.query(sql, [email], (err, results) => {
        if (err) throw err;
        if (results.length > 0) {
            const user = results[0];
            bcrypt.compare(pass, user.pass, (err, isMatch) => {
                if (err) throw err;
                if (isMatch) {
                    res.send('Login successful');
                } else {
                    res.send('Invalid credentials');
                }
            });
        } else {
            res.send('Invalid credentials');
        }
    });
});

// Generate OTP and send it via email
let currentOTP;
app.post('/forgot-password', (req, res) => {
    const { email } = req.body;
    const sql = 'SELECT * FROM userinfo WHERE mail = ?';

    db.query(sql, [email], (err, results) => {
        if (err) throw err;

        if (results.length > 0) {
            currentOTP = crypto.randomInt(100000, 999999).toString(); // Generate a 6-digit OTP
            const mailOptions = {
                from: 'lovelong4362684@gmail.com',
                to: email,
                subject: 'Your OTP for Password Reset',
                text: `Your OTP is ${currentOTP}`
            };

            transporter.sendMail(mailOptions, (error, info) => {
                if (error) {
                    console.log(error);
                    return res.status(500).send('Error sending OTP');
                }
                res.send('OTP sent to your email');
            });
        } else {
            res.status(400).send('Email not found');
        }
    });
});

// Reset password
app.post('/reset-password', (req, res) => {
    const { email, otp, newPassword, confirmPassword } = req.body;

    if (otp !== currentOTP) {
        return res.status(400).send('Invalid OTP');
    }

    if (newPassword !== confirmPassword) {
        return res.status(400).send('Passwords do not match');
    }

    bcrypt.hash(newPassword, 10, (err, hash) => {
        if (err) throw err;
        const sql = 'UPDATE userinfo SET pass = ? WHERE mail = ?';
        db.query(sql, [hash, email], (err, result) => {
            if (err) throw err;
            res.send('Password updated successfully');
        });
    });
});

app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});
