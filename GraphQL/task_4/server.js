import express from 'express';
import { graphql, buildSchema } from 'graphql';
import { verifyToken, authenticate, createToken, requireRole, requireAuth } from './src/util/auth.js';
import { createLoaders } from './src/loaders/loaders.js';
import { findByEmail as findUserByEmail, add as addUser } from './src/util/usersStore.js';

import { movieResolvers } from './src/resolvers/moviesResolver.js';
import { actorResolvers } from './src/resolvers/actorsResolver.js';
import { seriesResolvers } from './src/resolvers/seriesResolver.js';
import { episodeResolvers } from './src/resolvers/episodesResolver.js';

const protectedResolvers = {
  ...movieResolvers,
  ...actorResolvers,
  ...seriesResolvers,
  ...episodeResolvers,

  createMovie: (args, context) => { requireRole(context, 'ADMIN'); return movieResolvers.createMovie(args, context); },
  updateMovie: (args, context) => { requireRole(context, 'ADMIN'); return movieResolvers.updateMovie(args, context); },
  deleteMovie: (args, context) => { requireRole(context, 'ADMIN'); return movieResolvers.deleteMovie(args, context); },

  createActor: (args, context) => { requireRole(context, 'ADMIN'); return actorResolvers.createActor(args, context); },
  updateActor: (args, context) => { requireRole(context, 'ADMIN'); return actorResolvers.updateActor(args, context); },
  deleteActor: (args, context) => { requireRole(context, 'ADMIN'); return actorResolvers.deleteActor(args, context); },

  createSeries: (args, context) => { requireRole(context, 'ADMIN'); return seriesResolvers.createSeries(args, context); },
  updateSeries: (args, context) => { requireRole(context, 'ADMIN'); return seriesResolvers.updateSeries(args, context); },
  deleteSeries: (args, context) => { requireRole(context, 'ADMIN'); return seriesResolvers.deleteSeries(args, context); },

  createEpisode: (args, context) => { requireRole(context, 'ADMIN'); return episodeResolvers.createEpisode(args, context); },
  updateEpisode: (args, context) => { requireRole(context, 'ADMIN'); return episodeResolvers.updateEpisode(args, context); },
  deleteEpisode: (args, context) => { requireRole(context, 'ADMIN'); return episodeResolvers.deleteEpisode(args, context); },

  me: (_, context) => context.user ? { id: context.user.id, email: context.user.email, role: context.user.role } : null,

  login: async ({ input }) => {
    const { email, password } = input;
    const user = await authenticate(email, password);
    if (!user) {
      const err = new Error('Invalid credentials');
      err.extensions = { code: 'UNAUTHENTICATED' };
      throw err;
    }
    const token = createToken(user);
    return { token, user: { id: user.id, email: user.email, role: user.role, name: user.name } };
  },
};

const app = express();
app.use(express.json());

const schema = buildSchema(`
  type Movie { id: ID! title: String! year: Int! genre: String! actors: [Actor] }
  type Actor { id: ID! name: String! birthYear: Int! }
  type Series { id: ID! title: String! platform: String! episodes: [Episode] }
  type Episode { id: ID! title: String! episodeNumber: Int! }

  type User { id: ID!, email: String!, role: String!, name: String }
  type AuthPayload { token: String!, user: User! }

  input MovieInput { id: ID! title: String! year: Int! genre: String! actorIds: [ID!] }
  input ActorInput { id: ID! name: String! birthYear: Int! }
  input SeriesInput { id: ID! title: String! platform: String! }
  input EpisodeInput { id: ID! title: String! episodeNumber: Int! seriesId: ID! }
  input LoginInput { email: String!, password: String! }

  type Query {
    movie(id: ID!): Movie
    movies: [Movie]
    actor(id: ID!): Actor
    actors: [Actor]
    series(id: ID!): Series
    seriesList: [Series]
    episode(id: ID!): Episode
    episodeByNumber(seriesId: ID!, episodeNumber: Int!): Episode
    me: User
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

    login(input: LoginInput!): AuthPayload!
  }
`);

app.post('/seed-user', async (req, res) => {
  try {
    const { email, password, role = 'USER', name } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: 'email and password are required' });

    const existing = findUserByEmail(email);
    if (existing) {
      const updated = { ...existing, password, role, name };
      const { getAll, saveAll } = await import('./src/util/usersStore.js');
      const all = getAll().map(u => u.email === email ? updated : u);
      saveAll(all);
      return res.json({ id: updated.id, email, role: updated.role, name: updated.name });
    }
    const id = `u${Date.now()}`;
    const user = { id, email, password, role, name };
    addUser(user);
    res.json({ id, email, role, name });
  } catch (e) {
    res.status(500).json({ error: 'Failed to seed user' });
  }
});

app.post('/graphql', async (req, res) => {
  const { query, variables, operationName } = req.body;

  const authHeader = req.headers['authorization'] || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.substring(7) : null;
  const decoded = token ? verifyToken(token) : null;
  const user = decoded ? { id: decoded.sub, email: decoded.email, role: decoded.role } : null;

  const loaders = createLoaders();
  const result = await graphql({
    schema,
    source: query,
    rootValue: protectedResolvers,
    contextValue: {
      user,
      loaders,
    },
    variableValues: variables,
    operationName,
  });
  res.json(result);
});

app.listen(4000, () => console.log('Server running at http://localhost:4000/graphql'));
export default app;
