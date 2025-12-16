import { episodes } from '../mock/data.js';

export const episodesData = {
  getEpisodeById: (id) => episodes.find(e => e.id === id),
  getEpisodesBySeries: (seriesId) => episodes.filter(e => e.seriesId === seriesId),
  getEpisodeByNumber: (seriesId, number) => episodes.find(e => e.seriesId === seriesId && e.episodeNumber === number),
  createEpisode: (episode) => { episodes.push(episode); return episode; },
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
  }
};
