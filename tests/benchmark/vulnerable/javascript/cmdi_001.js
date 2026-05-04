// BENCHMARK: vulnerable - cmdi
const express = require('express');
const { exec } = require('child_process');
const app = express();

app.get('/run', (req, res) => {
    const cmd = req.query.cmd;
    exec('ls -la ' + cmd, (error, stdout, stderr) => {
        res.send(stdout);
    });
});

app.listen(3000);
