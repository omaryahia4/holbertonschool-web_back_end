const kue = require('kue');

const queue = kue.createQueue();
const job = {
  phoneNumber: '232548695',
  message: 'This is the code to verify your account',
};

const Newjob = queue.create('push_notification_code', job).save();

Newjob.on('enqueue', () => {
  console.log(`Notification job created: ${Newjob.id}`);
});

Newjob.on('complete', () => {
  console.log('Notification job completed');
});

Newjob.on('failed', () => {
  console.log('Notification job failed');
});
