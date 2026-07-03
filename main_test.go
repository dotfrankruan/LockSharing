package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

func generateTestKey(t *testing.T, email string) string {
	t.Helper()
	cfg := &packet.Config{RSABits: 2048}
	e, err := openpgp.NewEntity("Test User", "", email, cfg)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	var buf bytes.Buffer
	w, err := armor.Encode(&buf, openpgp.PublicKeyType, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Serialize(w); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

func newTestServer(t *testing.T) (*Server, *DB, func()) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	db, err := OpenDB(dbPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	srv := NewServer(db)
	return srv, db, func() { db.Close() }
}

func TestAddAndLookupByEmail(t *testing.T) {
	srv, db, cleanup := newTestServer(t)
	defer cleanup()

	email := "alice@example.com"
	armored := generateTestKey(t, email)

	rec := httptest.NewRecorder()
	form := url.Values{"keytext": {armored}}
	req := httptest.NewRequest(http.MethodPost, "/pks/add", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("add status = %d, body = %s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/pks/lookup?op=index&search="+email+"&options=mr", nil)
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("index status = %d, body = %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "pub:") {
		t.Fatalf("expected pub record, got:\n%s", body)
	}
	if !strings.Contains(body, "uid:") {
		t.Fatalf("expected uid record, got:\n%s", body)
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/pks/lookup?op=get&search="+email, nil)
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("get status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "BEGIN PGP PUBLIC KEY BLOCK") {
		t.Fatalf("expected armored key, got:\n%s", rec.Body.String())
	}

	// Verify key is importable back into GnuPG.
	var count int
	if err := db.conn.QueryRow("SELECT COUNT(*) FROM pubkeys").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("expected 1 pubkey, got %d", count)
	}
}

func TestLookupByFingerprintAndKeyID(t *testing.T) {
	srv, db, cleanup := newTestServer(t)
	defer cleanup()

	email := "bob@example.com"
	armored := generateTestKey(t, email)

	rec := httptest.NewRecorder()
	form := url.Values{"keytext": {armored}}
	req := httptest.NewRequest(http.MethodPost, "/pks/add", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	srv.ServeHTTP(rec, req)

	var fp, keyid string
	row := db.conn.QueryRow("SELECT fingerprint, keyid FROM pubkeys LIMIT 1")
	if err := row.Scan(&fp, &keyid); err != nil {
		t.Fatal(err)
	}

	for _, search := range []string{"0x" + fp, "0x" + keyid} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/pks/lookup?op=get&search="+search, nil)
		srv.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("get by %s status = %d, body = %s", search, rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "BEGIN PGP PUBLIC KEY BLOCK") {
			t.Fatalf("expected armored key for %s, got:\n%s", search, rec.Body.String())
		}
	}
}

func TestV2Endpoints(t *testing.T) {
	srv, _, cleanup := newTestServer(t)
	defer cleanup()

	email := "carol@example.com"
	armored := generateTestKey(t, email)

	rec := httptest.NewRecorder()
	form := url.Values{"keytext": {armored}}
	req := httptest.NewRequest(http.MethodPost, "/pks/add", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	srv.ServeHTTP(rec, req)

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/pks/v2/certs/by-identity/"+email, nil)
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("v2 by-identity status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "application/pgp-keys") {
		t.Fatalf("unexpected content-type %q", ct)
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodOptions, "/pks/v2/certs", nil)
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("options status = %d", rec.Code)
	}
	if allow := rec.Header().Get("Allow"); !strings.Contains(allow, "GET") {
		t.Fatalf("expected Allow header with GET, got %q", allow)
	}
}

func TestWebUIUploadAndSearch(t *testing.T) {
	srv, _, cleanup := newTestServer(t)
	defer cleanup()

	email := "web@example.com"
	armored := generateTestKey(t, email)

	// Upload via UI form.
	rec := httptest.NewRecorder()
	form := url.Values{"keytext": {armored}}
	req := httptest.NewRequest(http.MethodPost, "/ui/upload", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("upload status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "Submitted") {
		t.Fatalf("expected success message, got:\n%s", rec.Body.String())
	}

	// Search via UI form.
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/ui/search?q="+email, nil)
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("search status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "BEGIN PGP PUBLIC KEY BLOCK") {
		t.Fatalf("expected armored key in search results, got:\n%s", rec.Body.String())
	}

	// Root page should render.
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("index status = %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "LockSharing Keyserver") {
		t.Fatalf("expected UI title, got:\n%s", rec.Body.String())
	}
}

func TestNotFound(t *testing.T) {
	srv, _, cleanup := newTestServer(t)
	defer cleanup()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/pks/lookup?op=get&search=nobody@example.com", nil)
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}
}

func TestInvalidKey(t *testing.T) {
	srv, _, cleanup := newTestServer(t)
	defer cleanup()

	rec := httptest.NewRecorder()
	form := url.Values{"keytext": {"not a key"}}
	req := httptest.NewRequest(http.MethodPost, "/pks/add", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422, got %d", rec.Code)
	}
}
