const express = require('express');

const app = express();
const port = 1245;
app.get('/', ((req, res) => {
  res.send('Hello Holberton School!');
}));

app.listen(port, (error) => {
  if (error) {
    console.log('Something went wrong', error);
  } else {
    console.log(`Server is listening on port ${port}`);
  }
});
module.exports = app;
