-- Ranks country of origins by the number of non-unique fans
--life span is diff between split and formed
SELECT band_name,
		TIMESTAMPDIFF(YEAR, `formed`, `split`) AS lifespan FROM metal_bands
FROM metal_bands
WHERE style LIKE "%Glam rock%"
ORDER BY lifespan DESC;