-- Task 6

-- Creates a stored procedure 'Addbonus' that adds a new correction for a student
DELIMITER //

CREATE PROCEDURE AddBonus(IN user_id INT,
                        IN project_name VARCHAR(255), IN score INT)
BEGIN
    DECLARE project_id INT;
    SET project_id = NULL;
    SELECT id INTO project_id FROM projects WHERE name = project_name;
    IF project_id IS NOT NULL THEN
        INSERT INTO corrections (user_id, project_id, score) VALUES (user_id, project_id, score);
    ELSE
        INSERT INTO projects (name) VALUES (project_name);
        SET project_id = LAST_INSERT_ID();
        INSERT INTO corrections (user_id, project_id, score) VALUES (user_id, project_id, score);
    END IF;
END //

DELIMITER ;