import { seriesData } from '../data/seriesData.js';
import { episodesData } from '../data/episodesData.js';

export const seriesResolvers = {
  series: ({ id }) => seriesData.getSeriesById(id),
  seriesList: () => seriesData.getAllSeries(),
  createSeries: ({ input }) => seriesData.createSeries(input),
  updateSeries: ({ id, input }) => seriesData.updateSeries(id, input),
  deleteSeries: ({ id }) => seriesData.deleteSeries(id),
  Series: {
    episodes: (series) => episodesData.getEpisodesBySeries(series.id)
  }
};