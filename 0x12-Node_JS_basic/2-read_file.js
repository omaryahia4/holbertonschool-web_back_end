function countStudents(path) {
  try {
    // eslint-disable-next-line global-require
    const fs = require('fs');

    const csStudents = [];
    const sweStudents = [];
    const Field = { CS: csStudents, SWE: sweStudents };
    const data = fs.readFileSync(path, 'utf8');
    const students = data.split('\n').map((student) => student.split(','));
    students.shift();
    students.forEach((student) => {
      if (student[3] === 'CS') csStudents.push(student[0]);
      else sweStudents.push(student[0]);
    });
    console.log(`Number of students: ${students.length}`);
    // eslint-disable-next-line guard-for-in
    for (const key in Field) {
      console.log(
        `Number of students in ${key}: ${Field[key].length}. List: ${Field[
          key
        ].join(', ')}`,
      );
    }
  } catch (err) {
    throw new Error('Cannot load the database');
  }
}
module.exports = countStudents;
