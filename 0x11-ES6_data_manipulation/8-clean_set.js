export default function cleanSet(set, startString) {
  if (startString.length === 0) {
    return '';
  }
  const arr = [];
  set.forEach((element) => {
    if (element.startsWith(startString)) {
      arr.push(element.replace(startString, ''));
    }
  });
  return arr.join('-');
}
