export default function getStudentsByLocation(getListStudents, city) {
  return getListStudents.filter((value) => value.location === city);
}
