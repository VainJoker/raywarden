-- Raywarden has one owner. A constant unique index also serializes competing
-- first-account inserts. Existing multi-user databases must be reviewed before
-- this migration; failing the migration preserves every account.
CREATE UNIQUE INDEX users_single_owner ON users((1));
