import express from 'express';
import router from './routes/index';

const hostname = '127.0.0.1';
const port = 1245;
const app = express();

app.use('/', router);
app.listen(port, hostname);
export default app;
