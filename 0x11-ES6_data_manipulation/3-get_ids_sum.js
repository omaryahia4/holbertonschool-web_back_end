export default function getStudentIdsSum(getListStudents) {
  return getListStudents.reduce((accumulator, currentValue) => accumulator + currentValue.id, 0);
}
