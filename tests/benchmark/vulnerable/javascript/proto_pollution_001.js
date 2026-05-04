// BENCHMARK: vulnerable - proto_pollution
const express = require('express');
const app = express();

app.use(express.json());

app.post('/update-settings', (req, res) => {
    const settings = {};
    // Prototype pollution: attacker can set __proto__ properties
    Object.assign(settings, req.body);
    res.json({ status: 'updated', settings });
});

app.listen(3000);
