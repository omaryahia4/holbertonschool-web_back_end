export default class HolbertonCourse {
  constructor(name, length, students) {
    if (typeof name !== 'string') {
      throw Error('Name must be a string');
    }
    if (typeof length !== 'number') {
      throw Error('Length must be a number');
    }
    if (students.every((i) => (typeof i !== 'string'))) {
      throw Error('Students must be an Array of strings');
    }
    this._name = name;
    this._length = length;
    this._students = students;
  }

  get name() {
    return this._name;
  }

  get length() {
    return this._length;
  }

  get students() {
    return this._students;
  }

  set name(name) {
    if (typeof name !== 'string') {
      throw Error('Name must be a string');
    }
    this._name = name;
  }

  set length(length) {
    if (typeof length !== 'number') {
      throw Error('Length must be a number');
    }
    this._length = length;
  }

  set students(students) {
    if (students.every((i) => typeof i !== 'string')) {
      throw Error('Students must be an Array of strings');
    }
    this._students = students;
  }
}
