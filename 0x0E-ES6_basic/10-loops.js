export default function appendToEachArrayValue (array, appendString) {
  const arr = [];
  for (const s of array) {
    arr.push(appendString + s);
  }

  return arr;
}
