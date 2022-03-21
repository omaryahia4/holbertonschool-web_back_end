-- SQL script that creates an index idx_name_first on the table names and the first letter of name.

INSERT INTO names (`idx_name_first`)
VALUES (LEFT(name, 1));