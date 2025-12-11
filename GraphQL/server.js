import express from 'express';
import { graphql, buildSchema } from 'graphql';

const app = express();
const PORT = 4000;

app.use(express.json());

const schema = buildSchema(`
  type Query {
    hello: String
  }
`);

const rootValue = {
  hello: () => 'Hello graphQL!',
};

app.post('/graphql', async (req, res) => {
  const { query } = req.body;

  try {
    const result = await graphql({
      schema,
      source: query,
      rootValue,
    });
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}/graphql`);
});

export default app;