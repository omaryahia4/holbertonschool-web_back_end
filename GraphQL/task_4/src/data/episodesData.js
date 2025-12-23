import { episodes } from '../mock/data.js';

export const episodesData = {
  getEpisodeById: (id) => episodes.find(e => e.id === id),
  getAllEpisodes: () => episodes,
  createEpisode: (e) => { episodes.push(e); return e; },
  updateEpisode: (id, data) => {
    const ep = episodes.find(e => e.id === id);
    if (!ep) return null;
    Object.assign(ep, data);
    return ep;
  },
  deleteEpisode: (id) => {
    const index = episodes.findIndex(e => e.id === id);
    if (index === -1) return null;
    return episodes.splice(index, 1)[0];
  },

  getEpisodesBySeries: (seriesId) => episodes.filter(e => e.seriesId === seriesId)
};
