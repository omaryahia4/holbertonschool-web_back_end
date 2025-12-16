export const movies = [
  { id: "m1", title: "Inception", year: 2010, genre: "Sci-Fi", actorIds: ["a1", "a2"] },
  { id: "m2", title: "The Dark Knight", year: 2008, genre: "Action", actorIds: ["a2", "a3"] },
  { id: "m3", title: "Interstellar", year: 2014, genre: "Sci-Fi", actorIds: ["a3"] },
  { id: "m4", title: "Avengers: Endgame", year: 2019, genre: "Action", actorIds: ["a4", "a5"] },
  { id: "m5", title: "Iron Man", year: 2008, genre: "Action", actorIds: ["a4"] },
  { id: "m6", title: "The Matrix", year: 1999, genre: "Sci-Fi", actorIds: ["a6"] },
  { id: "m7", title: "Titanic", year: 1997, genre: "Romance", actorIds: ["a1"] },
  { id: "m8", title: "Guardians of the Galaxy", year: 2014, genre: "Action", actorIds: ["a5", "a7"] },
  { id: "m9", title: "Black Panther", year: 2018, genre: "Action", actorIds: ["a8"] },
  { id: "m10", title: "Doctor Strange", year: 2016, genre: "Action", actorIds: ["a4"] }
];

export const actors = [
  { id: "a1", name: "Leonardo DiCaprio", birthYear: 1974 },
  { id: "a2", name: "Christian Bale", birthYear: 1974 },
  { id: "a3", name: "Matthew McConaughey", birthYear: 1969 },
  { id: "a4", name: "Robert Downey Jr.", birthYear: 1965 },
  { id: "a5", name: "Chris Evans", birthYear: 1981 },
  { id: "a6", name: "Keanu Reeves", birthYear: 1964 },
  { id: "a7", name: "Zoe Saldana", birthYear: 1978 },
  { id: "a8", name: "Chadwick Boseman", birthYear: 1976 },
  { id: "a9", name: "Scarlett Johansson", birthYear: 1984 },
  { id: "a10", name: "Tom Holland", birthYear: 1996 }
];

export const series = [
  { id: "s1", title: "Stranger Things", platform: "Netflix" },
  { id: "s2", title: "Loki", platform: "Disney+" },
  { id: "s3", title: "The Witcher", platform: "Netflix" },
  { id: "s4", title: "WandaVision", platform: "Disney+" },
  { id: "s5", title: "Breaking Bad", platform: "Netflix" },
  { id: "s6", title: "The Mandalorian", platform: "Disney+" },
  { id: "s7", title: "Black Mirror", platform: "Netflix" },
  { id: "s8", title: "Hawkeye", platform: "Disney+" },
  { id: "s9", title: "Money Heist", platform: "Netflix" },
  { id: "s10", title: "Moon Knight", platform: "Disney+" }
];

export const episodes = [
  { id: "e1", seriesId: "s1", episodeNumber: 1, title: "Chapter One: The Vanishing" },
  { id: "e2", seriesId: "s1", episodeNumber: 2, title: "Chapter Two: The Weirdo" },
  { id: "e3", seriesId: "s2", episodeNumber: 1, title: "Glorious Purpose" },
  { id: "e4", seriesId: "s2", episodeNumber: 2, title: "The Variant" },
  { id: "e5", seriesId: "s3", episodeNumber: 1, title: "The End's Beginning" },
  { id: "e6", seriesId: "s3", episodeNumber: 2, title: "Four Marks" },
  { id: "e7", seriesId: "s4", episodeNumber: 1, title: "Filmed Before a Live Studio Audience" },
  { id: "e8", seriesId: "s4", episodeNumber: 2, title: "Don't Touch That Dial" },
  { id: "e9", seriesId: "s5", episodeNumber: 1, title: "Pilot" },
  { id: "e10", seriesId: "s5", episodeNumber: 2, title: "Cat's in the Bag..." }
];
