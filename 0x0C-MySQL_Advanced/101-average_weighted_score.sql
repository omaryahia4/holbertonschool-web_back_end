DELIMITER //

DROP PROCEDURE IF EXISTS ComputeAverageWeightedScoreForUsers//

-- so the average weighted score is the sum of projects weight multiplied by corrections score divided by the sum of projects weight
-- so in order to use projects weight for all students and corrections score i need to right join projects table with matching rows from corrections table

CREATE PROCEDURE ComputeAverageWeightedScoreForUsers()
BEGIN
    -- i will update average_score from table users for all students with the calculation of average weighted score
    UPDATE users
    SET average_score = (
        -- i will get all rows from projects table and the matching rows with the corrections table based on the project id where corrections user is is equal to users id
        SELECT SUM(projects.weight * corrections.score) / SUM(projects.weight) FROM corrections     
        RIGHT JOIN projects ON corrections.project_id = projects.id WHERE corrections.user_id = users.id
    );
END //

DELIMITER ;
