const express = require('express');
const bodyParser = require('body-parser');

const port = 7865;
const app = express();
app.use(bodyParser.json());

app.get('/', (request, response) => {
  response.send('Welcome to the payment system');
});

app.get('/cart/:id(\\d+)', (request, response) => {
  const { id } = request.params;
  response.send(`Payment methods for cart ${id}`);
});

app.get('/available_payments', (request, response) => {
  const object = {
    payment_methods: {
      credit_cards: true,
      paypal: false,
    }
  }
  response.send(object);
});

app.post('/login', (request, response) => {
  const username = req.body.userName;
  response.end(`Welcome ${username}`);
});

app.listen(port, () => {
  console.log('API available on localhost port 7865');
});

module.exports = app;