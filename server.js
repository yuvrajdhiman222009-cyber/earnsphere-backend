// server.js (backend)
require('dotenv').config();
const express = require('express');
const path = require('path');
const { Pool } = require('pg');        // Postgres
const bcrypt = require('bcrypt');
const session = require('express-session');
const Razorpay = require('razorpay');
const nodemailer = require('nodemailer');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 5000;

// ---------------- DB CONNECTION ----------------
const db = new Pool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT || 5432,
});

// ---------------- RAZORPAY ----------------
const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET
});

// ---------------- MIDDLEWARES ----------------
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(session({
  secret: process.env.SESSION_SECRET || 'change_this_secret',
  resave: false,
  saveUninitialized: true
}));

// Serve static frontend (optional if using Vercel separately)
app.use(express.static(path.join(__dirname, '../frontend')));

// ---------------- CREATE USERS TABLE ----------------
(async () => {
  try {
    await db.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        email VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        has_paid BOOLEAN DEFAULT false,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);
    console.log("✅ Users table ready");
  } catch (err) {
    console.error('DB init error:', err);
  }
})();

// ---------------- AUTH ROUTES ----------------
app.post('/register', async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) return res.status(400).send('All fields required');
  const hashed = await bcrypt.hash(password, 10);
  try {
    await db.query('INSERT INTO users (name,email,password) VALUES ($1,$2,$3)', [name,email,hashed]);
    res.send('Registration successful. Please proceed to payment.');
  } catch (e) {
    console.error(e);
    res.status(500).send('User exists or DB error');
  }
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const result = await db.query('SELECT * FROM users WHERE email=$1', [email]);
  if (result.rows.length === 0) return res.status(401).send('Invalid');
  const user = result.rows[0];
  const ok = await bcrypt.compare(password, user.password);
  if (!ok) return res.status(401).send('Invalid');
  req.session.userId = user.id;
  req.session.hasPaid = user.has_paid;
  res.send('Login successful');
});

// ---------------- PAYMENT ROUTES ----------------
app.post('/create-order', async (req, res) => {
  const amount = 20000; // ₹200 (paise me)
  try {
    const order = await razorpay.orders.create({ 
      amount, 
      currency: 'INR', 
      receipt: `rcpt_${Date.now()}` 
    });
    res.json(order);
  } catch (e) {
    console.error(e);
    res.status(500).send('Order creation failed');
  }
});

app.post('/payment-success', async (req, res) => {
  const { razorpay_payment_id, razorpay_order_id, razorpay_signature } = req.body;
  const sessionUserId = req.session.userId;
  if (!sessionUserId) return res.status(401).send('Login required');

  const generated_signature = crypto.createHmac('sha256', process.env.RAZORPAY_KEY_SECRET)
    .update(razorpay_order_id + '|' + razorpay_payment_id)
    .digest('hex');

  if (generated_signature !== razorpay_signature) {
    return res.status(400).send('Invalid signature');
  }

  try {
    await db.query('UPDATE users SET has_paid = true WHERE id = $1', [sessionUserId]);
    req.session.hasPaid = true;
    return res.json({ ok: true });
  } catch (e) {
    console.error(e);
    return res.status(500).send('DB error');
  }
});

// ---------------- CONTACT FORM ----------------
app.post('/contact', async (req, res) => {
  const { name, email, message } = req.body;
  if (!name || !email || !message) return res.status(400).send('All required');

  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: { 
      user: process.env.GMAIL_USER, 
      pass: process.env.GMAIL_APP_PASS 
    }
  });

  const mailOptions = {
    from: email,
    to: process.env.GMAIL_USER,
    subject: `Contact: ${name}`,
    text: `From: ${name} <${email}>\n\n${message}`
  };

  transporter.sendMail(mailOptions, (err) => {
    if (err) {
      console.error('Mail error', err);
      return res.status(500).send('Mail failed');
    }
    res.send('Message sent');
  });
});

// ---------------- PROTECTED DASHBOARD ----------------
app.get('/dashboard', (req, res) => {
  if (!req.session.userId) return res.redirect('/login.html');
  if (!req.session.hasPaid) return res.redirect('/payment.html');
  res.sendFile(path.join(__dirname, '../frontend/dashboard.html'));
});

// ---------------- START SERVER ----------------
app.listen(PORT, () => console.log(`🚀 Server running on http://localhost:${PORT}`));
