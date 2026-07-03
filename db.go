package main

import (
	"database/sql"
	"strings"

	_ "modernc.org/sqlite"
)

// DB wraps the SQLite database.
type DB struct {
	conn *sql.DB
}

// OpenDB opens (and creates) the SQLite database at the given path.
func OpenDB(path string) (*DB, error) {
	conn, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	if err := conn.Ping(); err != nil {
		return nil, err
	}
	db := &DB{conn: conn}
	if err := db.init(); err != nil {
		return nil, err
	}
	return db, nil
}

func (db *DB) init() error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS pubkeys (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			fingerprint TEXT NOT NULL UNIQUE,
			keyid TEXT NOT NULL,
			algorithm INTEGER,
			bitlength INTEGER,
			creation INTEGER,
			expiration INTEGER,
			keytext TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS uids (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			pubkey_id INTEGER NOT NULL,
			uid TEXT NOT NULL,
			email TEXT,
			FOREIGN KEY (pubkey_id) REFERENCES pubkeys(id) ON DELETE CASCADE
		)`,
		`CREATE INDEX IF NOT EXISTS idx_pubkeys_keyid ON pubkeys(keyid)`,
		`CREATE INDEX IF NOT EXISTS idx_pubkeys_fingerprint ON pubkeys(fingerprint)`,
		`CREATE INDEX IF NOT EXISTS idx_uids_uid ON uids(uid)`,
		`CREATE INDEX IF NOT EXISTS idx_uids_email ON uids(email)`,
	}
	for _, s := range stmts {
		if _, err := db.conn.Exec(s); err != nil {
			return err
		}
	}
	return nil
}

// StoreResult reports the outcome of storing a key.
type StoreResult struct {
	Fingerprint string `json:"fingerprint"`
	Inserted    bool   `json:"inserted"`
	Updated     bool   `json:"updated"`
}

// Store inserts or updates a parsed key and its User IDs.
func (db *DB) Store(info KeyInfo) (*StoreResult, error) {
	tx, err := db.conn.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	var existingID int64
	var existingKeytext string
	err = tx.QueryRow("SELECT id, keytext FROM pubkeys WHERE fingerprint = ?", info.Fingerprint).Scan(&existingID, &existingKeytext)
	inserted := false
	updated := false
	var pubkeyID int64

	if err == sql.ErrNoRows {
		res, err := tx.Exec(
			`INSERT INTO pubkeys (fingerprint, keyid, algorithm, bitlength, creation, expiration, keytext)
			 VALUES (?, ?, ?, ?, ?, ?, ?)`,
			info.Fingerprint, info.KeyID, info.Algorithm, info.BitLength, info.Creation, info.Expiration, info.Keytext,
		)
		if err != nil {
			return nil, err
		}
		pubkeyID, _ = res.LastInsertId()
		inserted = true
	} else if err != nil {
		return nil, err
	} else {
		_, err = tx.Exec(
			`UPDATE pubkeys SET keyid=?, algorithm=?, bitlength=?, creation=?, expiration=?, keytext=?
			 WHERE id=?`,
			info.KeyID, info.Algorithm, info.BitLength, info.Creation, info.Expiration, info.Keytext, existingID,
		)
		if err != nil {
			return nil, err
		}
		pubkeyID = existingID
		_, _ = tx.Exec("DELETE FROM uids WHERE pubkey_id=?", existingID)
		updated = true
	}

	for _, uid := range info.UIDs {
		_, err = tx.Exec(
			"INSERT INTO uids (pubkey_id, uid, email) VALUES (?, ?, ?)",
			pubkeyID, uid.Name, uid.Email,
		)
		if err != nil {
			return nil, err
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &StoreResult{Fingerprint: info.Fingerprint, Inserted: inserted, Updated: updated}, nil
}

// StoredKey represents a key as returned from the database.
type StoredKey struct {
	Fingerprint string
	KeyID       string
	Algorithm   int
	BitLength   int
	Creation    int64
	Expiration  int64
	Keytext     string
}

// lookup returns keys matching an exact SQL condition. The condition is
// appended after "WHERE 1=1 " and must use parameter placeholders.
func (db *DB) lookup(where string, args ...any) ([]StoredKey, error) {
	query := `SELECT fingerprint, keyid, algorithm, bitlength, creation, expiration, keytext FROM pubkeys ` + where
	rows, err := db.conn.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var keys []StoredKey
	for rows.Next() {
		var k StoredKey
		if err := rows.Scan(&k.Fingerprint, &k.KeyID, &k.Algorithm, &k.BitLength, &k.Creation, &k.Expiration, &k.Keytext); err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	return keys, rows.Err()
}

// LookupByFingerprint searches by primary key fingerprint (full or suffix).
func (db *DB) LookupByFingerprint(fp string) ([]StoredKey, error) {
	fp = strings.ToUpper(fp)
	if len(fp) == 40 || len(fp) == 64 {
		return db.lookup("WHERE fingerprint = ?", fp)
	}
	return db.lookup("WHERE fingerprint LIKE '%' || ?", fp)
}

// LookupByKeyID searches by 64-bit (or longer) Key ID.
func (db *DB) LookupByKeyID(keyID string) ([]StoredKey, error) {
	keyID = strings.ToUpper(keyID)
	return db.lookup("WHERE keyid = ? OR keyid LIKE '%' || ?", keyID, keyID)
}

// LookupByUID searches by full User ID string or email (case-insensitive).
func (db *DB) LookupByUID(uid string) ([]StoredKey, error) {
	uid = strings.ToLower(uid)
	rows, err := db.conn.Query(`
		SELECT p.fingerprint, p.keyid, p.algorithm, p.bitlength, p.creation, p.expiration, p.keytext
		FROM pubkeys p
		JOIN uids u ON u.pubkey_id = p.id
		WHERE lower(u.uid) = ? OR lower(u.email) = ?
		GROUP BY p.id`, uid, uid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var keys []StoredKey
	for rows.Next() {
		var k StoredKey
		if err := rows.Scan(&k.Fingerprint, &k.KeyID, &k.Algorithm, &k.BitLength, &k.Creation, &k.Expiration, &k.Keytext); err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	return keys, rows.Err()
}

// Stats returns basic keyserver statistics.
func (db *DB) Stats() (int, error) {
	var count int
	err := db.conn.QueryRow("SELECT COUNT(*) FROM pubkeys").Scan(&count)
	return count, err
}

// Close closes the underlying database connection.
func (db *DB) Close() error {
	return db.conn.Close()
}
