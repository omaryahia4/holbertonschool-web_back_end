async function countStudents(path) {
  return new Promise((resolve, reject) => {
    // eslint-disable-next-line global-require
    const fs = require('fs');
    fs.readFile(path, 'utf8', (err, data) => {
      if (err) {
        reject(new Error('Cannot load the database'));
        return;
      }
      const csStudents = [];
      const sweStudents = [];
      const Field = { CS: csStudents, SWE: sweStudents };
      const students = data.split('\n').map((student) => student.split(','));
      students.shift();
      students.forEach((student) => {
        if (student[3] === 'CS') csStudents.push(student[0]);
        else sweStudents.push(student[0]);
      });
      const result = [];
      result.push(`Number of students: ${students.length}`);
      // eslint-disable-next-line guard-for-in
      for (const key in Field) {
        result.push(
          `Number of students in ${key}: ${Field[key].length}. List: ${Field[
            key
          ].join(', ')}`,
        );
      }
      const final = result.join('\n');
      console.log(final);
      resolve(final);
    });
  });
}
module.exports = countStudents;
