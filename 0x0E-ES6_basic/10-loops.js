export default function appendToEachArrayValue(array, appendString) {
  const arr = [];
  for (const str of array) {
    newArray.push(appendString + str);
  }

  return arr;
}
