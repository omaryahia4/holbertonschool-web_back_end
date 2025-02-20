import readDatabase from '../utils';

class StudentsController {
  static getAllStudents(request, response, file) {
    const studentsBySpe = [];
    readDatabase(file)
      .then((data) => {
        studentsBySpe.push('This is the list of our students');
        Object.entries(data).sort().forEach(([key, values]) => {
          studentsBySpe.push(`Number of students in ${key}: ${values.length}. List: ${values.join(', ')}`);
        });
        response.status(200).end(`${studentsBySpe.join('\n')}`);
      })
      .catch((error) => {
        response.status(500).end(error.message);
      });
  }

  static getAllStudentsByMajor(request, response, file) {
    const { major } = request.params;
    if (major !== 'CS' && major !== 'SWE') {
      response.status(500).end('Major parameter must be CS or SWE');
    }
    readDatabase(file)
      .then((data) => {
        response.status(200).send(`List: ${data[major].join(', ')}`);
      })
      .catch((error) => {
        response.status(500).send(error.message);
      });
  }
}
export default StudentsController;