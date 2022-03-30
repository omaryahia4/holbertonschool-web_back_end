export default function handleResponseFromAPI(promise) {
  return promise.then(() => {
    return ({ status: 200, body: 'Success' });
  }).catch(() => {
    new Error();
  }).finally(() => {
    console.log('Got a response from the API');
  });
}
