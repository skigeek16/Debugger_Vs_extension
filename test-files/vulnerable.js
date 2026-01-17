// Test file with intentional security vulnerabilities
// Used to test SemgrepGuard extension

const express = require('express');
const mysql = require('mysql');
const exec = require('child_process').exec;

const app = express();

// SQL Injection Vulnerability
app.get('/user', (req, res) => {
    const userId = req.query.id;
    // VULNERABLE: SQL injection
    const query = `SELECT * FROM users WHERE id = ${userId}`;
    connection.query(query, (err, results) => {
        res.json(results);
    });
});

// Command Injection
app.get('/ping', (req, res) => {
    const host = req.query.host;
    // VULNERABLE: Command injection
    exec(`ping -c 1 ${host}`, (err, stdout) => {
        res.send(stdout);
    });
});

// XSS Vulnerability
app.get('/greet', (req, res) => {
    const name = req.query.name;
    // VULNERABLE: Reflected XSS
    res.send(`<h1>Hello ${name}</h1>`);
});

// Hardcoded Secret
const JWT_SECRET = "super-secret-key-123";  // VULNERABLE

// Path Traversal
app.get('/file', (req, res) => {
    const filename = req.query.name;
    // VULNERABLE: Path traversal
    res.sendFile(`/app/files/${filename}`);
});

// Insecure Crypto
const crypto = require('crypto');
function encrypt(text) {
    // VULNERABLE: Using weak algorithm
    const cipher = crypto.createCipher('des', 'password');
    return cipher.update(text, 'utf8', 'hex') + cipher.final('hex');
}

app.listen(3000);
