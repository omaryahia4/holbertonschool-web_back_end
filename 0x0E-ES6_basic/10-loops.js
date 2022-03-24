export default function appendToEachArrayValue(array, appendString) {
  const Arr = [];
  for (const str of array) {
    Arr.push(appendString + str);
  }

  return Arr;
}
