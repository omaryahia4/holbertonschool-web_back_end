export default function appendToEachArrayValue (array, appendString) {
  const arr = [];
  for (const str of array) {
    arr.push(appendString + str);
  }

  return arr;
}
