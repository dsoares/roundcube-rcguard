-- PostgreSQL table for rcguard

DROP TABLE IF EXISTS rcguard CASCADE;
CREATE TABLE rcguard (
	ip
		varchar(15)
		NOT NULL
		PRIMARY KEY,
	first
		timestamp with time zone
		NOT NULL,
	last
		timestamp with time zone
		NOT NULL,
	hits
		integer
		NOT NULL
);

CREATE INDEX
	indx_rcguard_last
ON
	rcguard(last);
