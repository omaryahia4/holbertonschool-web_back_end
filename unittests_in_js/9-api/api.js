const express = require("express");

const app = express();
const port = 7865;

app.get("/", (req, res) => {
  res.send("Welcome to the payment system");
});

app.get("/cart/:id", (req, res) => {
  const id = parseInt(req.params.id);

  if (isNaN(id)) {
    res.status(404).end();
  } else {
    res.send(`Payment methods for cart ${id}`);
  }
});

app.listen(port, () => {
  console.log("API available on localhost port 7865");
});
