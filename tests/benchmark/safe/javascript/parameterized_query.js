// BENCHMARK: safe - parameterized_query
const express = require('express');
const { Pool } = require('pg');
const app = express();
const pool = new Pool();

app.use(express.json());

app.post('/login', async (req, res) => {
    const { username } = req.body;
    // Safe: parameterized query with $1 placeholder
    const result = await pool.query(
        'SELECT * FROM users WHERE username = $1',
        [username]
    );
    res.json(result.rows);
});

app.listen(3000);
