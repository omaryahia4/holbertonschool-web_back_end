const kue = require('kue');

const queue = kue.createQueue();
const job = {
  phoneNumber: '',
  message: '',
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
