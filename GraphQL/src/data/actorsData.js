import { actors } from '../mock/data.js';

export const actorsData = {
  getActorById: (id) => actors.find(a => a.id === id),
  getAllActors: () => actors,
  createActor: (actor) => { actors.push(actor); return actor; },
  updateActor: (id, data) => {
    const actor = actors.find(a => a.id === id);
    if (!actor) return null;
    Object.assign(actor, data);
    return actor;
  },
  deleteActor: (id) => {
    const index = actors.findIndex(a => a.id === id);
    if (index === -1) return null;
    return actors.splice(index, 1)[0];
  }
};
