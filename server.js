const express = require("express");
const mysql = require("mysql");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");

const app = express();

// Ensure that your React app's origin is allowed
app.use(cors({
  origin: 'http://localhost:3000', // React app URL
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  credentials: true // Allows cookies/auth headers to be sent
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
// MySQL connection setup
const db = mysql.createConnection({
  host: "127.0.0.1", // Server host
  user: "root", // MySQL username
  password: "root", // MySQL password (adjust as needed)
  database: "users", // Database name
  port: 3309, // Port for phpMyAdmin MariaDB connection
});

// Connect to MySQL
db.connect((err) => {
  if (err) {
    console.error('Error connecting to MySQL:', err);
    return;
  }
  console.log("MySQL Connected");
});


// Register Route
app.post("/register", (req, res) => {
  console.log(req.body);
  const { name, email, tel, password, confirmPass } = req.body;

  if (password !== confirmPass) {
    return res.status(400).send("Passwords do not match");
  }

  // Hash password before saving it
  const hashedPassword = bcrypt.hashSync(password, 10);

  const sql = "INSERT INTO users (name, email, phone, password) VALUES (?, ?, ?, ?)";

  db.query(sql, [name, email, tel, hashedPassword], (err, result) => {
    if (err) {
      console.error(err);
      if (err.code === "ER_DUP_ENTRY") {
        return res.status(400).send("User already exists");
      }
      return res.status(500).send("Error registering user");
    }
    res.status(201).send("User registered...");
  });
});

// Login Route
app.post("/login", (req, res) => {
  const { email, pass } = req.body;

  const sql = "SELECT * FROM users WHERE email = ?";
  db.query(sql, [email], (err, results) => {
    if (err) return res.status(500).send("Database error");
    if (results.length === 0) return res.status(400).send("Invalid email or password");

    const user = results[0];
    const isPasswordValid = bcrypt.compareSync(pass, user.password);

    if (!isPasswordValid) return res.status(400).send("Invalid email or password");

    const token = jwt.sign({ id: user.id }, "secretKey", { expiresIn: "1h" });
    res.send({ message: "Login successful", token });
  });
});

// Start the server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
