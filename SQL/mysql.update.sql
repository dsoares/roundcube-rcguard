-- MySQL table updates for rcguard

-- 0.1.0 -> 0.1.1
TRUNCATE TABLE `rcguard`;

ALTER TABLE `rcguard`
  DROP INDEX `time`,
  DROP INDEX `hits`;

ALTER TABLE `rcguard`
  ADD INDEX (`last`),
  ADD INDEX (`hits`);

-- 0.2.0 -> 0.2.1
TRUNCATE TABLE `rcguard`;

ALTER TABLE `rcguard`
  DROP INDEX `last`,
  DROP INDEX `hits`;

ALTER TABLE `rcguard`
  ADD INDEX `last_index` (`last`),
  ADD INDEX `hits_index` (`hits`);
