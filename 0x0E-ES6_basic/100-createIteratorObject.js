export default function createIteratorObject(report) {
  const employee = [];
  for (const key of Object.keys(report.allEmployees)) {
    employee.push(...report.allEmployees[key]);
  }
  return employee;
}
