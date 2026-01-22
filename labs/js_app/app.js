const express = require('express');
const _ = require('lodash');

const app = express();

app.get('/', (req, res) => {
  const data = _.merge({}, req.query);
  res.json({ message: 'Hello World', data });
});

app.listen(3000, () => {
  console.log('Server running on port 3000');
});