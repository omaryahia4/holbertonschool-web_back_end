import { movies } from '../mock/data.js';

export const moviesData = {
  getMovieById: (id) => movies.find(m => m.id === id),
  getAllMovies: () => movies,
  createMovie: (movie) => { movies.push(movie); return movie; },
  updateMovie: (id, data) => {
    const movie = movies.find(m => m.id === id);
    if (!movie) return null;
    Object.assign(movie, data);
    return movie;
  },
  deleteMovie: (id) => {
    const index = movies.findIndex(m => m.id === id);
    if (index === -1) return null;
    return movies.splice(index, 1)[0];
  }
};
