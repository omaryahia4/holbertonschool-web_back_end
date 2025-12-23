import DataLoader from 'dataloader';
import { actorsData } from '../data/actorsData.js';
import { episodesData } from '../data/episodesData.js';

export const createLoaders = () => ({
  actorById: new DataLoader(async (ids) => {
    const allActors = actorsData.getAllActors();
    return ids.map(id => allActors.find(a => a.id === id) || new Error(`Actor ${id} not found`));
  }),

  episodesBySeriesId: new DataLoader(async (seriesIds) => {
    const allEpisodes = episodesData.getAllEpisodes();
    return seriesIds.map(id => allEpisodes.filter(e => e.seriesId === id));
  })
});
