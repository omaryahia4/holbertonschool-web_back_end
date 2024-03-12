-- 3. Old school band
SELECT band_name, IFNULL(split, 2020) - IFNULL(formed, 0) AS lifespan 
FROM metal_bands 
WHERE style LIKE '%Glam rock%';