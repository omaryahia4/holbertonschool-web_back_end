import signUpUser from './4-user-promise';
import uploadPhoto from './5-photo-reject';
export default async function handleProfileSignup(firstName, lastName, fileName) {
  const arr = [];
  arr.push({ status: 'fulfilled', value: await signUpUser(firstName, lastName).then((response) => response) }, { status: 'rejected', value: await uploadPhoto(fileName).catch((err) => err) });
  return arr;
}
