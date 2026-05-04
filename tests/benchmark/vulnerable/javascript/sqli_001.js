// BENCHMARK: vulnerable - sqli
const express = require('express');
const { Pool } = require('pg');
const app = express();
const pool = new Pool();

app.use(express.json());

app.post('/login', async (req, res) => {
    const { username } = req.body;
    const result = await pool.query(`SELECT * FROM users WHERE username = '${username}'`);
    res.json(result.rows);
});

app.listen(3000);
