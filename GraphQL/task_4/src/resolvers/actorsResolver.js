import { actorsData } from '../data/actorsData.js';

export const actorResolvers = {
  actor: ({ id }) => actorsData.getActorById(id),
  actors: () => actorsData.getAllActors(),
  createActor: ({ input }) => actorsData.createActor(input),
  updateActor: ({ id, input }) => actorsData.updateActor(id, input),
  deleteActor: ({ id }) => actorsData.deleteActor(id)
};
