import { seriesData } from '../data/seriesData.js';

export const seriesResolvers = {
  // Root query: series by ID
  series: (source, args) => {
    const { id } = args;
    return seriesData.getSeriesById(id);
  },

  // Root query: all series
  seriesList: () => seriesData.getAllSeries(),

  // Mutation: create series
  createSeries: (source, args) => {
    const { input } = args;
    return seriesData.createSeries(input);
  },

  // Mutation: update series
  updateSeries: (source, args) => {
    const { id, input } = args;
    return seriesData.updateSeries(id, input);
  },

  // Mutation: delete series
  deleteSeries: (source, args) => {
    const { id } = args;
    return seriesData.deleteSeries(id);
  },

  // Field resolver: episodes of a series
  Series: {
    episodes: async (parent, args, context) => {
      // Use DataLoader from context
      const episodes = await context.loaders.episodesBySeriesId.load(parent.id);
      return episodes;
    }
  }
};
