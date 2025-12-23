import { seriesData } from '../data/seriesData.js';

export const seriesResolvers = {
  series: async (args, context) => {
    const { id } = args;
    const s = seriesData.getSeriesById(id);
    if (!s) return null;
    const eps = await context.loaders.episodesBySeriesId.load(s.id);
    return { ...s, episodes: eps };
  },
  seriesList: async (args, context) => {
    const list = seriesData.getAllSeries();
    return Promise.all(list.map(async (s) => {
      const eps = await context.loaders.episodesBySeriesId.load(s.id);
      return { ...s, episodes: eps };
    }));
  },
  createSeries: (source, args) => {
    const { input } = args;
    return seriesData.createSeries(input);
  },
  updateSeries: (source, args) => {
    const { id, input } = args;
    return seriesData.updateSeries(id, input);
  },
  deleteSeries: (source, args) => {
    const { id } = args;
    return seriesData.deleteSeries(id);
  },
  Series: {
    episodes: async (parent, args, context) => {
      const episodes = await context.loaders.episodesBySeriesId.load(parent.id);
      return episodes;
    }
  }
};
