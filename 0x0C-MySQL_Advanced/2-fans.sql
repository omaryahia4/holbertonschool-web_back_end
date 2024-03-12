-- SQL script that ranks country origins of bands, ordered by the number of (non-unique) fans

SELECT `origin`, SUM(fans) as nb_fans
FROM `metal_bands` GROUP BY `origin` -- Collect all bands from same origin in one column
ORDER BY `nb_fans` DESC; -- order them with number of fans