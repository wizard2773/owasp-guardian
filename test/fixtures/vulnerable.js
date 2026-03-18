// ── test/fixtures/vulnerable.js ── intentionally vulnerable code for CLI testing

const express = require('express');
const crypto  = require('crypto');
const fs      = require('fs');
const jwt     = require('jsonwebtoken');
const { exec } = require('child_process');

const app = express();
app.use(express.json());

// A02-001: Hardcoded secret
const JWT_SECRET = 'my-super-secret-password-123';
const DB_PASS    = 'admin123';

// A03-001: SQL Injection
app.get('/user', async (req, res) => {
  const query = "SELECT * FROM users WHERE id = " + req.query.id;
  const result = await db.query(query);
  res.json(result);
});

// A03-002: Command Injection
app.post('/convert', (req, res) => {
  exec('convert ' + req.body.filename + ' output.pdf', (err, stdout) => {
    res.send(stdout);
  });
});

// A03-003: XSS
app.get('/search', (req, res) => {
  document.getElementById('results').innerHTML = req.query.q;
});

// A03-004: eval()
app.post('/calculate', (req, res) => {
  const result = eval(req.body.expression);
  res.json({ result });
});

// A01-002: CORS wildcard
app.use(require('cors')({ origin: '*' }));

// A02-002: Weak hash
function hashPassword(password) {
  return crypto.createHash('md5').update(password).digest('hex');
}

// A02-003: Insecure random for session token
function generateSessionToken() {
  return Math.random().toString(36).substr(2, 16);
}
// generates a secret token  ^ (this should be flagged)

// A05-001: Debug mode
const isDev = true;
app.set('env', 'development');

// A07-001: JWT none algorithm
function verifyToken(token) {
  return jwt.verify(token, JWT_SECRET, { algorithms: ['none'] });
}

// A07-002: Weak password policy
function validatePassword(pass) {
  if (pass.length < 6) throw new Error('Too short');
}

// A05-003: Stack trace to client
app.use((err, req, res, next) => {
  res.status(500).json({ error: err.message, stack: err.stack });
});

// A09-001: Credentials in logs
app.post('/login', (req, res) => {
  console.log('Login attempt:', req.body.password, req.body.token);
});

// A10-001: SSRF
app.get('/proxy', async (req, res) => {
  const response = await fetch(req.query.url);
  res.send(await response.text());
});

// A04-001: Mass Assignment
app.put('/user/:id', async (req, res) => {
  await User.update(req.params.id, req.body);
  res.json({ success: true });
});

app.listen(3000);
