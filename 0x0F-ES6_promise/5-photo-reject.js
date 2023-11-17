export default function uploadPhoto(fileName) {
  return new Promise((reject) => 
  reject(Error(`${fileName} cannot be processed`)));
}
