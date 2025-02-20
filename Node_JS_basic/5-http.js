const http = require('http');
const process = require('process');
const countStudents = require('./3-read_file_async');

const hostname = '127.0.0.1';
const port = 1245;
const file = process.argv[2];

const app = http.createServer((request, response) => {
  response.statusCode = 200;
  response.setHeader('Content-Type', 'text/plain');

  const { url } = request;

  if (url === '/') {
    response.end('Hello Holberton School!');
  } else if (url === '/students') {
    response.write('This is the list of our students\n');
    countStudents(file)
      .then((data) => {
        response.end(`${data.join('\n')}`);
      })
      .catch((error) => {
        response.end(`${error.message}`);
      });
  }
});

app.listen(port, hostname);
module.exports = app;