-- SQL script that lists all bands with Glam rock as their main style,
-- ranked by their longevity


-- if the have splited we use split else we use current year 2023
SELECT band_name, IFNULL(split, 2023) - IFNULL(formed, 0) AS lifespan
FROM metal_bands
WHERE style LIKE '%Glam rock%'
ORDER BY lifespan DESC;