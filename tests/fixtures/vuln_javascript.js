// Intentionally vulnerable JavaScript — used for test fixtures ONLY
const express = require('express');
const { exec } = require('child_process');
const fs = require('fs');
const app = express();

// SQLi via template literal
app.get('/user', (req, res) => {
  const id = req.query.id;
  db.query(`SELECT * FROM users WHERE id = ${id}`, (err, rows) => res.json(rows));
});

// CMDi via exec
app.post('/convert', (req, res) => {
  const file = req.body.file;
  exec(`convert ${file} output.png`, (err, stdout) => res.send(stdout));
});

// XSS via innerHTML
app.get('/search', (req, res) => {
  const q = req.query.q;
  res.send(`<div id="r"></div><script>document.getElementById('r').innerHTML='${q}'</script>`);
});

// Path traversal
app.get('/download', (req, res) => {
  const name = req.query.name;
  res.send(fs.readFileSync(name));
});

const DB_PASSWORD = "super-secret-password-123";
const AWS_KEY = "AKIAIOSFODNN7EXAMPLE";
