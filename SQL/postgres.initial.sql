-- PostgreSQL table for rcguard
-- edit table and indexes so the prefix is added to it if you have done so in Roundcube

CREATE TABLE rcguard (
    ip character varying(40) NOT NULL,
    first timestamp with time zone NOT NULL,
    last timestamp with time zone NOT NULL,
    hits integer NOT NULL
);

ALTER TABLE ONLY rcguard
    ADD CONSTRAINT rcguard_pkey PRIMARY KEY (ip);

CREATE INDEX rcguard_last_idx ON rcguard(last);
CREATE INDEX rcguard_hits_idx ON rcguard(hits);
