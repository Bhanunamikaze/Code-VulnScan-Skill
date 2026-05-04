// BENCHMARK: vulnerable - open_redirect
const express = require('express');
const app = express();

app.get('/login', (req, res) => {
    const next = req.query.next || '/dashboard';
    // No validation of the redirect URL
    res.redirect(next);
});

app.listen(3000);
