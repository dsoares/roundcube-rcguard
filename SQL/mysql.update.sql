-- MySQL table updates for rcguard

-- 0.1.0 -> 0.1.1
TRUNCATE TABLE `rcguard`;

ALTER TABLE `rcguard`
  DROP INDEX `time`,
  DROP INDEX `hits`;

ALTER TABLE `rcguard`
  ADD INDEX (`last`),
  ADD INDEX (`hits`);
