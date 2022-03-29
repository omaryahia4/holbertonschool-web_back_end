export default function getFullResponseFromAPI(success) {
  const prom = new Promise((resolve, reject) => {
    if (success) {
      resolve({ status: 200, body: 'Success' });
    }
    else {
      reject(Error('The fake API is not working currently'));
    }
  });
  return prom;
}
