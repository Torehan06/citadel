package store

// 0009: IAM and STS.
//
// IAM entities (users, groups, roles, managed policies, instance profiles and
// the smaller account-level objects) are JSON documents keyed by account, kind
// and a lookup key: the lower-cased name, because IAM names are unique without
// regard to case. Relationships that belong to one entity (tags, inline
// policies, attachments) live inside its document, so every IAM mutation is a
// read-modify-write of a few rows in one transaction.
//
// Access keys stay in access_keys so SigV4 lookup is unchanged. kind says whose
// key it is: 'root' (bootstrap identities, which act as their account's root),
// 'user' (an IAM user's key) or 'session' (STS temporary credentials, which
// also carry a session token, an expiry and the assumed-role identity).
func init() {
	register(9, "iam", `
CREATE TABLE iam_entities (
	account_id TEXT NOT NULL,
	kind       TEXT NOT NULL,
	key        TEXT NOT NULL,
	doc        TEXT NOT NULL,
	created    INTEGER NOT NULL,
	PRIMARY KEY (account_id, kind, key)
);

ALTER TABLE access_keys ADD COLUMN kind TEXT NOT NULL DEFAULT 'root';
ALTER TABLE access_keys ADD COLUMN session_token TEXT NOT NULL DEFAULT '';
ALTER TABLE access_keys ADD COLUMN expires INTEGER NOT NULL DEFAULT 0;
ALTER TABLE access_keys ADD COLUMN principal TEXT NOT NULL DEFAULT '';
ALTER TABLE access_keys ADD COLUMN last_used INTEGER NOT NULL DEFAULT 0;
ALTER TABLE access_keys ADD COLUMN last_service TEXT NOT NULL DEFAULT '';
ALTER TABLE access_keys ADD COLUMN last_region TEXT NOT NULL DEFAULT '';
`)
}
