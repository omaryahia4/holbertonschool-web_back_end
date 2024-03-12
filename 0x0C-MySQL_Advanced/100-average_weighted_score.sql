-- Creates a stored procedure ComputeAverageWeightedScoreForUser that computes and store the average weighted score for a student.
DELIMITER //
CREATE PROCEDURE ComputeAverageWeightedScoreForUser(user_id INT)
BEGIN
-- i will update users table and set the average score calculation for the given student id
    UPDATE users
    SET
        average_score = (SELECT sum((SELECT weight FROM projects WHERE corrections.project_id = id) * score)
         / 
         (SELECT sum(weight) FROM projects) FROM corrections WHERE corrections.user_id = user_id)
    WHERE
        id = user_id;
END//
DELIMITER ;
