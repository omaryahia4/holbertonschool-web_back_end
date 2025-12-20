import { moviesData } from '../data/moviesData.js';
import { actorsData } from '../data/actorsData.js';

export const movieResolvers = {
  movie: ({ id }) => {
    const movie = moviesData.getMovieById(id);
    if (!movie) return null;
    return { 
      ...movie, 
      actors: movie.actorIds.map(aid => actorsData.getActorById(aid))
    };
  },

  movies: () => {
    return moviesData.getAllMovies().map(m => ({
      ...m,
      actors: m.actorIds.map(aid => actorsData.getActorById(aid))
    }));
  },

  createMovie: ({ input }) => {
    const newMovie = moviesData.createMovie(input);
    return { 
      ...newMovie, 
      actors: newMovie.actorIds.map(aid => actorsData.getActorById(aid))
    };
  },

  updateMovie: ({ id, input }) => {
    const updated = moviesData.updateMovie(id, input);
    return { 
      ...updated, 
      actors: updated.actorIds.map(aid => actorsData.getActorById(aid))
    };
  },

  deleteMovie: ({ id }) => {
    const deleted = moviesData.deleteMovie(id);
    return { 
      ...deleted, 
      actors: deleted.actorIds.map(aid => actorsData.getActorById(aid))
    };
  }
};