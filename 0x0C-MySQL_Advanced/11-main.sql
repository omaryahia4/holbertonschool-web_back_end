-- Test view
SELECT * FROM need_meeting;

SELECT "--";
/* ADD BOB TO THE LIST */
UPDATE students SET score = 40 WHERE name = 'Bob';
SELECT * FROM need_meeting;

SELECT "--";
/* REMOVE STEEVE FROM THE LIST */
UPDATE students SET score = 80 WHERE name = 'Steeve';
SELECT * FROM need_meeting;

SELECT "--";
/* REMOVE JEAN FROM THE LIST */
UPDATE students SET last_meeting = CURDATE() WHERE name = 'Jean';
SELECT * FROM need_meeting;

SELECT "--";
/* ADD JEAN TO THE LIST */
UPDATE students SET last_meeting = ADDDATE(CURDATE(), INTERVAL -2 MONTH) WHERE name = 'Jean';
SELECT * FROM need_meeting;

SELECT "--";

SHOW CREATE TABLE need_meeting;

SELECT "--";

SHOW CREATE TABLE students;