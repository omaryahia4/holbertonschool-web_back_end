process.stdout.write('Welcome to Holberton School, what is your name?\n');
process.stdin.on('readable', () => {
  const yourName = process.stdin.read();
  process.stdout.write(`Your name is: ${yourName}`);
});
process.on('exit', () => {
  process.stdout.write('This important software is now closing\n');
});
