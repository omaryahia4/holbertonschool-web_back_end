import express from 'express';
import { graphql, buildSchema } from 'graphql';

import { movieResolvers } from './src/resolvers/moviesResolver.js';
import { actorResolvers } from './src/resolvers/actorsResolver.js';
import { seriesResolvers } from './src/resolvers/seriesResolver.js';
import { episodeResolvers } from './src/resolvers/episodesResolver.js';

const rootValue = {
  ...movieResolvers,
  ...actorResolvers,
  ...seriesResolvers,
  ...episodeResolvers
};

const app = express();
app.use(express.json());

const schema = buildSchema(`
  type Movie { id: ID! title: String! year: Int! genre: String! actors: [Actor] }
  type Actor { id: ID! name: String! birthYear: Int! }
  type Series { id: ID! title: String! platform: String! episodes: [Episode] }
  type Episode { id: ID! title: String! episodeNumber: Int! }

  input MovieInput { id: ID! title: String! year: Int! genre: String! actorIds: [ID!] }
  input ActorInput { id: ID! name: String! birthYear: Int! }
  input SeriesInput { id: ID! title: String! platform: String! }
  input EpisodeInput { id: ID! title: String! episodeNumber: Int! seriesId: ID! }

  type Query {
    movie(id: ID!): Movie
    movies: [Movie]
    actor(id: ID!): Actor
    actors: [Actor]
    series(id: ID!): Series
    seriesList: [Series]
    episode(id: ID!): Episode
    episodeByNumber(seriesId: ID!, episodeNumber: Int!): Episode
  }

  type Mutation {
    createMovie(input: MovieInput): Movie
    updateMovie(id: ID!, input: MovieInput): Movie
    deleteMovie(id: ID!): Movie

    createActor(input: ActorInput): Actor
    updateActor(id: ID!, input: ActorInput): Actor
    deleteActor(id: ID!): Actor

    createSeries(input: SeriesInput): Series
    updateSeries(id: ID!, input: SeriesInput): Series
    deleteSeries(id: ID!): Series

    createEpisode(input: EpisodeInput): Episode
    updateEpisode(id: ID!, input: EpisodeInput): Episode
    deleteEpisode(id: ID!): Episode
  }
`);

app.post('/graphql', async (req, res) => {
  const { query, variables, operationName } = req.body;
  const result = await graphql({ schema, source: query, rootValue, variableValues: variables, operationName });
  res.json(result);
});

app.listen(4000, () => console.log('Server running at http://localhost:4000/graphql'));
export default app