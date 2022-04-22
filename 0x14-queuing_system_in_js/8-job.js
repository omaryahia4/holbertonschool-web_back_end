export default function createPushNotificationsJobs(jobs, queue) {
  if (!Array.isArray(jobs)) {
    throw Error('Jobs is not an array');
  }
  jobs.forEach((job) => {
    const Job = queue.create('push_notification_code_3', job).save();
    Job.on('enqueue', () => {
      console.log(`Notification job created: ${Job.id}`);
    });
    Job.on('complete', () => {
      console.log(`Notification job ${Job.id} completed`);
    });
    Job.on('failed', (err) => {
      console.log(`Notification job ${job.id} failed: ${err}`);
    });
    Job.on('progress', (progress) => {
      console.log(`Notification job ${Job.id} ${progress}% complete`);
    });
  });
}
