import { moviesData } from '../data/moviesData.js';

export const movieResolvers = {
  movie: async (args, context) => {
    const { id } = args;
    const movie = moviesData.getMovieById(id);
    if (!movie) return null;
    const actors = await context.loaders.actorById.loadMany(movie.actorIds);
    return { ...movie, actors };
  },
  movies: async (args, context) => {
    const allMovies = moviesData.getAllMovies();
    return Promise.all(
      allMovies.map(async (movie) => {
        const actors = await context.loaders.actorById.loadMany(movie.actorIds);
        return { ...movie, actors };
      })
    );
  },
  createMovie: async (args, context) => {
    const { input } = args;
    const newMovie = moviesData.createMovie(input);
    const actors = await context.loaders.actorById.loadMany(newMovie.actorIds);
    return { ...newMovie, actors };
  },
  updateMovie: async (args, context) => {
    const { id, input } = args;
    const updatedMovie = moviesData.updateMovie(id, input);
    const actors = await context.loaders.actorById.loadMany(updatedMovie.actorIds);
    return { ...updatedMovie, actors };
  },
  deleteMovie: async (args, context) => {
    const { id } = args;
    const deletedMovie = moviesData.deleteMovie(id);
    const actors = await context.loaders.actorById.loadMany(deletedMovie.actorIds);
    return { ...deletedMovie, actors };
  }
};
