package store

import (
	"context"
	"database/sql"
	"errors"

	"citadel/internal/bootstrap"
)

// Account is an AWS-style account as the data plane sees it.
type Account struct {
	ID          string
	CanonicalID string
	DisplayName string
	Email       string
}

// Principal is who signed a request: an access key and the account it belongs to.
type Principal struct {
	AccessKey string
	UserName  string
	Account   Account
}

// SeedIdentities upserts the bootstrap accounts and access keys. Seeding is
// idempotent, so a region can restart with the same file any number of times.
func (s *Store) SeedIdentities(ctx context.Context, f *bootstrap.File) error {
	if f == nil {
		return nil
	}
	return s.Update(ctx, func(tx *Tx) error {
		now := tx.HLC().WallMs()
		for _, a := range f.Accounts {
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO accounts(id, name, canonical_id, display_name, email) VALUES (?, ?, ?, ?, ?)
				ON CONFLICT(id) DO UPDATE SET name=excluded.name, canonical_id=excluded.canonical_id,
					display_name=excluded.display_name, email=excluded.email`,
				a.ID, a.Name, a.CanonicalID, a.DisplayName, a.Email); err != nil {
				return err
			}
			for _, u := range a.Users {
				if _, err := tx.ExecContext(ctx, `
					INSERT INTO access_keys(access_key, secret_key, account_id, user_name, created) VALUES (?, ?, ?, ?, ?)
					ON CONFLICT(access_key) DO UPDATE SET secret_key=excluded.secret_key,
						account_id=excluded.account_id, user_name=excluded.user_name`,
					u.AccessKey, u.SecretKey, a.ID, u.Name, now); err != nil {
					return err
				}
			}
			if err := tx.Change("iam", "SeedAccount", a.ID, map[string]any{"users": len(a.Users)}); err != nil {
				return err
			}
		}
		return nil
	})
}

// ErrNotFound is returned by lookups that match nothing.
var ErrNotFound = errors.New("store: not found")

// LookupKey returns the secret and principal for an active access key.
func (s *Store) LookupKey(ctx context.Context, accessKey string) (secret string, p Principal, err error) {
	err = s.r.QueryRowContext(ctx, `
		SELECT k.secret_key, k.user_name, a.id, a.canonical_id, a.display_name, a.email
		FROM access_keys k JOIN accounts a ON a.id = k.account_id
		WHERE k.access_key = ? AND k.status = 'Active'`, accessKey).
		Scan(&secret, &p.UserName, &p.Account.ID, &p.Account.CanonicalID, &p.Account.DisplayName, &p.Account.Email)
	if errors.Is(err, sql.ErrNoRows) {
		return "", Principal{}, ErrNotFound
	}
	p.AccessKey = accessKey
	return secret, p, err
}

// AccountByID returns an account.
func (s *Store) AccountByID(ctx context.Context, id string) (Account, error) {
	return s.accountWhere(ctx, `id = ?`, id)
}

// AccountByCanonicalID returns the account with this S3 canonical user ID.
func (s *Store) AccountByCanonicalID(ctx context.Context, canonicalID string) (Account, error) {
	return s.accountWhere(ctx, `canonical_id = ?`, canonicalID)
}

// AccountByEmail returns the account registered with this email address.
func (s *Store) AccountByEmail(ctx context.Context, email string) (Account, error) {
	return s.accountWhere(ctx, `email = ? COLLATE NOCASE`, email)
}

func (s *Store) accountWhere(ctx context.Context, where string, arg any) (Account, error) {
	var a Account
	err := s.r.QueryRowContext(ctx,
		`SELECT id, canonical_id, display_name, email FROM accounts WHERE `+where+` LIMIT 1`, arg).
		Scan(&a.ID, &a.CanonicalID, &a.DisplayName, &a.Email)
	if errors.Is(err, sql.ErrNoRows) {
		return Account{}, ErrNotFound
	}
	return a, err
}
