export default function updateUniqueItems(map) {
  try {
    map.forEach((value, key) => {
      if (value === 1) { map.set(key, 100); }
    });
  } catch (e) {
    throw Error('Cannot process');
  }
}
