import { episodesData } from '../data/episodesData.js';

export const episodeResolvers = {
  episode: ({ id }) => episodesData.getEpisodeById(id),
  episodeByNumber: ({ seriesId, episodeNumber }) => episodesData.getEpisodeByNumber(seriesId, episodeNumber),
  createEpisode: ({ input }) => episodesData.createEpisode(input),
  updateEpisode: ({ id, input }) => episodesData.updateEpisode(id, input),
  deleteEpisode: ({ id }) => episodesData.deleteEpisode(id)
};
