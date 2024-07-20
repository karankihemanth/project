const express = require('express');
const bodyParser = require('body-parser');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const path = require('path');
const Twilio=require('twilio');
const nodemailer=require('nodemailer');
const accountSid = 'AC8423a3e65b5e8342dc6b16334327d44c'; // Your Twilio Account SID
const authToken = '17e7dd04c126e94f4ea24c1b4054a5b6';
const client=Twilio(accountSid,authToken); 
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
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});
app.use(express.static('public'));

// Utility function to generate OTP
function generateOTP() {
    return Math.floor(100000 + Math.random() * 900000).toString();
}
// Register route
app.post('/register', (req, res) => {
    const { name, email, tel, pass, confirmPass } = req.body;

    if (!name || !email || !tel || !pass || !confirmPass) {
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
            const sql = 'INSERT INTO userinfo (name, mail, pass, phone) VALUES (?, ?, ?, ?)';
            db.query(sql, [name, email, hash, tel], (err, result) => {
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
function sendOTP(phoneNumber, otp, res) {
    // Ensure phoneNumber is in E.164 format
    const formattedPhoneNumber = `+91${phoneNumber}`; // Assuming phoneNumber is 10-digit Indian number

    client.messages.create({
        body: `Your OTP code is ${otp}`,
        from: '+12673231435', // Replace with your valid Twilio phone number
        to: formattedPhoneNumber
    })
    .then(message => {
        console.log(`OTP sent to ${formattedPhoneNumber}: ${message.sid}`);
        res.send({ success: true, message: 'OTP sent successfully' });
    })
    .catch(error => {
        console.error('Error sending OTP:', error);
        // Handle specific Twilio errors
        if (error.code === 21266) {
            res.status(400).send({ success: false, message: 'To and From numbers cannot be the same' });
        } else if (error.code === 21659) {
            res.status(400).send({ success: false, message: 'Invalid Twilio phone number or short code country mismatch' });
        } else {
            res.status(500).send({ success: false, message: 'Failed to send OTP' });
        }
    });
}
// In-memory store for OTPs with timestamps
const otpStore = {};

// Send OTP route
app.post('/send-otp', (req, res) => {
    const { phoneNumber } = req.body;

    if (!phoneNumber) {
        return res.status(400).send('Phone number is required');
    }

    const sql = 'SELECT * FROM userinfo WHERE phone = ?';
    db.query(sql, [phoneNumber], (err, results) => {
        if (err) {
            console.error('Error checking phone number:', err);
            return res.status(500).send('Internal server error');
        }

        if (results.length === 0) {
            return res.status(404).send({ success: false, message: 'Phone number not found' });
        } else {
            const otp = generateOTP();
            const timestamp = Date.now();
            otpStore[phoneNumber] = { otp, timestamp }; // Store OTP and timestamp in-memory

            // Call sendOTP function with res object to handle response
            sendOTP(phoneNumber, otp, res);
            console.log(`OTP for ${phoneNumber}: ${otp}`); // For development purposes, log the OTP
        }
    });
});

// Verify OTP route
app.post('/verify-otp', (req, res) => {
    const { phoneNumber, otp } = req.body;

    if (!phoneNumber || !otp) {
        return res.status(400).send('Phone number and OTP are required');
    }

    const storedData = otpStore[phoneNumber];

    if (storedData) {
        const { otp: storedOtp, timestamp } = storedData;
        const currentTime = Date.now();
        const timeDifference = currentTime - timestamp;

        if (timeDifference > 2 * 60 * 1000) { // Check if OTP is older than 2 minutes
            delete otpStore[phoneNumber]; // Delete expired OTP
            return res.status(400).send({ success: false, message: 'OTP has expired' });
        }

        if (storedOtp === otp) {
            res.send({ success: true, message: 'OTP verified successfully' });
        } else {
            res.status(400).send({ success: false, message: 'Invalid OTP' });
        }
    } else {
        res.status(400).send({ success: false, message: 'Invalid OTP' });
    }
});

// Update password route
app.post('/update-password', (req, res) => {
    const { phoneNumber, newPassword } = req.body;

    if (!phoneNumber || !newPassword) {
        return res.status(400).send('Phone number and new password are required');
    }

    bcrypt.hash(newPassword, 10, (err, hash) => {
        if (err) throw err;

        const sql = 'UPDATE userinfo SET pass = ? WHERE phone = ?';
        db.query(sql, [hash, phoneNumber], (err, result) => {
            if (err) throw err;
            res.send({ success: true, message: 'Password updated successfully' });
        });
    });
});

app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});
