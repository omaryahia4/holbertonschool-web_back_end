import { moviesData } from '../data/moviesData.js';

export const movieResolvers = {
  // Root query: movie by ID
  movie: async (args, context) => {
    const { id } = args;
    const movie = moviesData.getMovieById(id);
    if (!movie) return null;

    // Use DataLoader from context
    const actors = await context.loaders.actorById.loadMany(movie.actorIds);
    return { ...movie, actors };
  },

  // Root query: all movies
  movies: async (args, context) => {
    const allMovies = moviesData.getAllMovies();
    return Promise.all(
      allMovies.map(async (movie) => {
        const actors = await context.loaders.actorById.loadMany(movie.actorIds);
        return { ...movie, actors };
      })
    );
  },

  // Mutation: create a movie
  createMovie: async (args, context) => {
    const { input } = args;
    const newMovie = moviesData.createMovie(input);

    const actors = await context.loaders.actorById.loadMany(newMovie.actorIds);
    return { ...newMovie, actors };
  },

  // Mutation: update a movie
  updateMovie: async (args, context) => {
    const { id, input } = args;
    const updatedMovie = moviesData.updateMovie(id, input);

    const actors = await context.loaders.actorById.loadMany(updatedMovie.actorIds);
    return { ...updatedMovie, actors };
  },

  // Mutation: delete a movie
  deleteMovie: async (args, context) => {
    const { id } = args;
    const deletedMovie = moviesData.deleteMovie(id);

    const actors = await context.loaders.actorById.loadMany(deletedMovie.actorIds);
    return { ...deletedMovie, actors };
  }
};
