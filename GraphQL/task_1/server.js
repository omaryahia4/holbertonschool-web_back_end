import express from 'express';
import { graphql, buildSchema } from 'graphql';

const app = express();
const PORT = 4000;

app.use(express.json());

const schema = buildSchema(`
  type Movie {
    id: ID!
    title: String!
    year: Int!
    genre: String!
  }

  type Actor {
    id: ID!
    name: String!
    birthYear: Int!
  }

  type Query {
    movie(id: ID!): Movie
    movies: [Movie]
    actor(id: ID!): Actor
    actors: [Actor]
  }
`);

const moviesData = [
  { id: "1", title: "Inception", year: 2010, genre: "Sci-Fi" },
  { id: "2", title: "The Dark Knight", year: 2008, genre: "Action" },
  { id: "3", title: "Interstellar", year: 2014, genre: "Sci-Fi" }
];

const actorsData = [
  { id: "1", name: "Leonardo DiCaprio", birthYear: 1974 },
  { id: "2", name: "Christian Bale", birthYear: 1974 },
  { id: "3", name: "Matthew McConaughey", birthYear: 1969 }
];


const rootValue = {
  movie: ({ id }) => moviesData.find(m => m.id === id),
  movies: () => moviesData,

  actor: ({ id }) => actorsData.find(a => a.id === id),
  actors: () => actorsData
};

app.post('/graphql', async (req, res) => {
  try {
    const { query, variables, operationName } = req.body || {};

    const result = await graphql({
      schema,
      source: query,
      rootValue,
      variableValues: variables,
      operationName
    });

    res.status(200).json(result);
  } catch (err) {
    res.status(500).json({ errors: [{ message: err.message }] });
  }
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}/graphql`);
});

export default app;