-- SQL script that creates a trigger that resets the attribute valid_email only when the email has been changed.
-- 

-- By default, mysql recognizes the semicolon as a statement delimiter,
-- so you must redefine the delimiter temporarily to cause mysql to pass the entire stored program definition to the server.
DELIMITER //

-- i will create a trigger that set the valid_email attribute to zero when the email has changed
CREATE TRIGGER update_email
BEFORE UPDATE ON users
FOR EACH ROW
BEGIN
    IF OLD.email != NEW.email 
    THEN
	SET NEW.valid_email = 0;
    END IF;
END
//
DELIMITER ;
