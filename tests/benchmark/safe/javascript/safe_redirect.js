// BENCHMARK: safe - allowlist_redirect
const express = require('express');
const app = express();

const ALLOWED_REDIRECTS = ['/dashboard', '/profile', '/settings', '/home'];

app.get('/login', (req, res) => {
    const next = req.query.next || '/dashboard';
    // Safe: redirect only to allowlisted internal paths
    if (ALLOWED_REDIRECTS.includes(next)) {
        res.redirect(next);
    } else {
        res.redirect('/dashboard');
    }
});

app.listen(3000);
