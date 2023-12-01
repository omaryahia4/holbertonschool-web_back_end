const express = require('express');

const port = 7865;
const app = express();

app.get('/', (request, response) => {
  response.send('Welcome to the payment system');
});

app.get('/cart/:id(\\d+)', (request, response) => {
  const { id } = request.params;
  response.send(`Payment methods for cart ${id}`);
});


app.listen(port, () => {
  console.log('API available on localhost port 7865');
});

module.exports = app;