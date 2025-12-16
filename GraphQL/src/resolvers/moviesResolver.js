import { moviesData } from '../data/moviesData.js';
import { actorsData } from '../data/actorsData.js';

export const movieResolvers = {
  movie: ({ id }) => moviesData.getMovieById(id),
  movies: () => moviesData.getAllMovies(),
  createMovie: ({ input }) => moviesData.createMovie(input),
  updateMovie: ({ id, input }) => moviesData.updateMovie(id, input),
  deleteMovie: ({ id }) => moviesData.deleteMovie(id),
  Movie: {
    actors: (movie) => movie.actorIds.map(id => actorsData.getActorById(id))
  }
};
