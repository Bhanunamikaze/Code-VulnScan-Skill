// BENCHMARK: vulnerable - xss
const express = require('express');
const app = express();

app.get('/search', (req, res) => {
    const query = req.query.q;
    res.send(`<div id="result"></div>
<script>
  document.getElementById('result').innerHTML = '${query}';
</script>`);
});

app.listen(3000);
