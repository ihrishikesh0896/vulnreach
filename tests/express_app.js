const express = require('express');
const app = express();
const router = express.Router();

app.get('/health', (req, res) => res.send('ok'));
router.post('/items/:id', (req, res) => res.send(req.params.id));
app.use('/api', router);

module.exports = app;

