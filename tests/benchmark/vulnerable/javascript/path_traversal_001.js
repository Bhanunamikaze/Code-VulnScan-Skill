// BENCHMARK: vulnerable - path_traversal
const express = require('express');
const fs = require('fs');
const app = express();

app.get('/file/:name', (req, res) => {
    const filename = req.params.name;
    fs.readFile('/var/data/' + filename, 'utf8', (err, data) => {
        if (err) return res.status(404).send('Not found');
        res.send(data);
    });
});

app.listen(3000);
