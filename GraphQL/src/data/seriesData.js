import { series } from '../mock/data.js';

export const seriesData = {
  getSeriesById: (id) => series.find(s => s.id === id),
  getAllSeries: () => series,
  createSeries: (s) => { series.push(s); return s; },
  updateSeries: (id, data) => {
    const s = series.find(s => s.id === id);
    if (!s) return null;
    Object.assign(s, data);
    return s;
  },
  deleteSeries: (id) => {
    const index = series.findIndex(s => s.id === id);
    if (index === -1) return null;
    return series.splice(index, 1)[0];
  }
};
