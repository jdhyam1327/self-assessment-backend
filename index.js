require("dotenv").config();
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");

const app = express();
app.use(express.json());
app.use(cors({ 
    origin: "*", 
    methods: ["GET", "POST"], 
    allowedHeaders: ["Content-Type", "Authorization"] 
}));

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { require: true }
});

const SECRET_KEY = "3d216879c4c9f20351b8dfedb4fc5cee";

// Signup Route
app.post("/signup", async (req, res) => {
    const { name, email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    try {
        await pool.query(
            "INSERT INTO users (name, email, password) VALUES ($1, $2, $3)",
            [name, email, hashedPassword]
        );
        res.json({ message: "User registered!" });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Signup failed" });
    }
});


// Login Route
app.post("/login", async (req, res) => {
    const { email, password } = req.body;
    const user = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
    if (user.rows.length === 0) return res.status(401).json({ error: "Invalid credentials" });

    const isValid = await bcrypt.compare(password, user.rows[0].password);
    if (!isValid) return res.status(401).json({ error: "Invalid credentials" });

    const token = jwt.sign({ userId: user.rows[0].id }, SECRET_KEY, { expiresIn: "1h" });
    res.json({ token, userId: user.rows[0].id });
});

app.get("/test-db", async (req, res) => {
    try {
        const result = await pool.query("SELECT NOW()");
        res.json({ message: "Database connected!", time: result.rows[0] });
    } catch (err) {
        console.error("Database connection error:", err);
        res.status(500).json({ error: "Failed to connect to database" });
    }
});


// Start server
app.listen(5000, () => console.log("Backend running on port 5000"));

