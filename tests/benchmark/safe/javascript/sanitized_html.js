// BENCHMARK: safe - sanitized_html_output
const express = require('express');
const app = express();

function escapeHtml(str) {
    return str
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

app.get('/search', (req, res) => {
    const query = req.query.q || '';
    // Safe: HTML-escaped before being placed in innerHTML context
    const safeQuery = escapeHtml(query);
    res.send(`<div id="result">Results for: ${safeQuery}</div>`);
});

app.listen(3000);
