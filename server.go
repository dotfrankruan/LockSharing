package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
)

// Server implements the HKP HTTP API.
type Server struct {
	db *DB
}

// NewServer creates a new keyserver HTTP handler.
func NewServer(db *DB) *Server {
	s := &Server{db: db}
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/":
		s.handleUIIndex(w, r)
	case "/ui/upload":
		s.handleUIUpload(w, r)
	case "/ui/search":
		s.handleUISearch(w, r)
	case "/pks/add":
		s.handleAdd(w, r)
	case "/pks/lookup":
		s.handleLookup(w, r)
	default:
		if strings.HasPrefix(r.URL.Path, "/pks/v2/") {
			s.handleV2(w, r)
			return
		}
		http.NotFound(w, r)
	}
}

func (s *Server) handleAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	keytext := r.PostFormValue("keytext")
	if strings.TrimSpace(keytext) == "" {
		http.Error(w, "missing keytext", http.StatusBadRequest)
		return
	}

	infos, err := parseKeytext(keytext)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	if len(infos) == 0 {
		http.Error(w, "no keys found", http.StatusUnprocessableEntity)
		return
	}

	var results []StoreResult
	for _, info := range infos {
		res, err := s.db.Store(info)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		results = append(results, *res)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	resp := map[string]any{
		"inserted": results,
	}
	_ = json.NewEncoder(w).Encode(resp)
}

func (s *Server) handleLookup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	q := r.URL.Query()
	op := q.Get("op")
	search := q.Get("search")

	switch op {
	case "get", "hget":
		s.handleLookupGet(w, r, search)
	case "index", "vindex":
		s.handleLookupIndex(w, r, search)
	case "stats":
		s.handleLookupStats(w, r)
	default:
		http.Error(w, "unsupported operation", http.StatusNotImplemented)
	}
}

func (s *Server) handleLookupGet(w http.ResponseWriter, r *http.Request, search string) {
	keys, err := s.searchKeys(search)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if len(keys) == 0 {
		http.NotFound(w, r)
		return
	}

	var keytexts []string
	for _, k := range keys {
		keytexts = append(keytexts, k.Keytext)
	}
	entities, err := parseEntities(keytexts)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	bundle, err := armorBundle(entities)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/pgp-keys")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(bundle))
}

func (s *Server) handleLookupIndex(w http.ResponseWriter, r *http.Request, search string) {
	keys, err := s.searchKeys(search)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if len(keys) == 0 {
		http.NotFound(w, r)
		return
	}

	mr := strings.Contains(r.URL.Query().Get("options"), "mr")
	if mr {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Content-Type", "text/plain")
		_ = s.writeMachineReadableIndex(w, keys)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = s.writeHTMLIndex(w, keys)
}

func (s *Server) handleLookupStats(w http.ResponseWriter, r *http.Request) {
	count, err := s.db.Stats()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"count":      count,
		"server":     "LockSharing",
		"version":    "0.2.0",
		"components": []string{"legacy", "v2"},
	})
}

// searchKeys resolves a legacy search string to stored keys.
func (s *Server) searchKeys(search string) ([]StoredKey, error) {
	search = strings.TrimSpace(search)
	if search == "" {
		return nil, nil
	}

	if strings.HasPrefix(search, "0x") || strings.HasPrefix(search, "0X") {
		hex := normalizeHex(search)
		if !isHex(hex) {
			return nil, nil
		}
		switch len(hex) {
		case 16:
			return s.db.LookupByKeyID(hex)
		case 32, 40, 64:
			return s.db.LookupByFingerprint(hex)
		default:
			// Treat unknown hex length as a fingerprint suffix.
			return s.db.LookupByFingerprint(hex)
		}
	}

	return s.db.LookupByUID(search)
}

func (s *Server) handleV2(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/pks/v2/")
	parts := strings.SplitN(path, "/", 2)
	if len(parts) == 0 {
		http.Error(w, "missing category", http.StatusBadRequest)
		return
	}
	category := parts[0]

	if r.Method == http.MethodOptions {
		s.handleV2Options(w, r, category)
		return
	}

	if len(parts) != 2 {
		http.Error(w, "missing identifier", http.StatusForbidden)
		return
	}
	identifier := parts[1]

	switch category {
	case "certs":
		s.handleV2Certs(w, r, identifier)
	case "canonical":
		s.handleV2Canonical(w, r, identifier)
	case "index":
		s.handleV2Index(w, r, identifier)
	default:
		http.Error(w, "unsupported category", http.StatusNotImplemented)
	}
}

func (s *Server) handleV2Options(w http.ResponseWriter, r *http.Request, category string) {
	switch category {
	case "certs", "canonical", "index":
		w.Header().Set("Allow", "GET, HEAD, OPTIONS")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.WriteHeader(http.StatusOK)
	default:
		http.Error(w, "unsupported category", http.StatusNotImplemented)
	}
}

func (s *Server) handleV2Certs(w http.ResponseWriter, r *http.Request, identifier string) {
	// identifier is "by-identity/<email>", "by-keyid/<id>", or "by-vfingerprint/<vfp>".
	parts := strings.SplitN(identifier, "/", 2)
	if len(parts) != 2 {
		http.Error(w, "invalid identifier", http.StatusBadRequest)
		return
	}
	sub := parts[0]
	value := parts[1]

	var keys []StoredKey
	var err error
	switch sub {
	case "by-identity":
		keys, err = s.db.LookupByUID(value)
	case "by-keyid":
		keys, err = s.db.LookupByKeyID(normalizeHex(value))
	case "by-vfingerprint":
		keys, err = s.db.LookupByFingerprint(stripVFingerprint(value))
	default:
		http.Error(w, "unsupported certs category", http.StatusNotImplemented)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if len(keys) == 0 {
		http.NotFound(w, r)
		return
	}

	entities, err := storedKeysToEntities(keys)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	data, err := serializeBinaryBundle(entities)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/pgp-keys;armor=no")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func (s *Server) handleV2Canonical(w http.ResponseWriter, r *http.Request, identity string) {
	keys, err := s.db.LookupByUID(identity)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if len(keys) == 0 {
		http.NotFound(w, r)
		return
	}
	entities, err := storedKeysToEntities(keys)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	data, err := serializeBinaryBundle(entities)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/pgp-keys;armor=no")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func (s *Server) handleV2Index(w http.ResponseWriter, r *http.Request, identity string) {
	keys, err := s.db.LookupByUID(identity)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if len(keys) == 0 {
		http.NotFound(w, r)
		return
	}
	idx, err := s.buildV2Index(keys)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(idx)
}

func storedKeysToEntities(keys []StoredKey) ([]*openpgp.Entity, error) {
	var texts []string
	for _, k := range keys {
		texts = append(texts, k.Keytext)
	}
	return parseEntities(texts)
}

func stripVFingerprint(vf string) string {
	vf = normalizeHex(vf)
	if len(vf) >= 2 {
		return vf[2:]
	}
	return vf
}

// writeMachineReadableIndex emits the legacy machine-readable index format.
func (s *Server) writeMachineReadableIndex(w io.Writer, keys []StoredKey) error {
	fmt.Fprintf(w, "info:1:%d\n", len(keys))
	now := time.Now().Unix()
	for _, k := range keys {
		flags := keyFlags(k, now)
		fmt.Fprintf(w, "pub:%s:%d:%d:%d:%s:%s\n", k.Fingerprint, k.Algorithm, k.BitLength, k.Creation, zeroIfZero(k.Expiration), flags)
		uids, err := s.lookupUIDs(k.Fingerprint)
		if err != nil {
			return err
		}
		for _, uid := range uids {
			uflags := uidFlags(uid)
			fmt.Fprintf(w, "uid:%s::::%s\n", escapeIndexField(uid.Name), uflags)
		}
	}
	return nil
}

func (s *Server) writeHTMLIndex(w io.Writer, keys []StoredKey) error {
	fmt.Fprintln(w, "<html><body><h1>LockSharing Key Index</h1><ul>")
	for _, k := range keys {
		fmt.Fprintf(w, "<li><a href=\"/pks/lookup?op=get&search=0x%s\">%s</a> (%d/%d)</li>\n", k.Fingerprint, k.Fingerprint, k.Algorithm, k.BitLength)
	}
	fmt.Fprintln(w, "</ul></body></html>")
	return nil
}

func (s *Server) lookupUIDs(fp string) ([]UIDInfo, error) {
	rows, err := s.db.conn.Query(`
		SELECT u.uid, u.email FROM uids u
		JOIN pubkeys p ON p.id = u.pubkey_id
		WHERE p.fingerprint = ?`, fp)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var uids []UIDInfo
	for rows.Next() {
		var uid UIDInfo
		if err := rows.Scan(&uid.Name, &uid.Email); err != nil {
			return nil, err
		}
		uids = append(uids, uid)
	}
	return uids, rows.Err()
}

func keyFlags(k StoredKey, now int64) string {
	var flags []byte
	if k.Expiration > 0 && k.Expiration < now {
		flags = append(flags, 'e')
	}
	return string(flags)
}

func uidFlags(uid UIDInfo) string {
	var flags []byte
	if uid.Revoked {
		flags = append(flags, 'r')
	}
	if uid.Expired {
		flags = append(flags, 'e')
	}
	return string(flags)
}

func zeroIfZero(v int64) string {
	if v == 0 {
		return ""
	}
	return strconv.FormatInt(v, 10)
}

func escapeIndexField(s string) string {
	s = strings.ReplaceAll(s, "%", "%25")
	s = strings.ReplaceAll(s, ":", "%3A")
	return s
}

// buildV2Index builds a JSON index response from stored keys.
func (s *Server) buildV2Index(keys []StoredKey) ([]map[string]any, error) {
	var out []map[string]any
	for _, k := range keys {
		u, err := s.lookupUIDs(k.Fingerprint)
		if err != nil {
			return nil, err
		}
		var uids []map[string]any
		for _, uid := range u {
			uids = append(uids, map[string]any{
				"uidString": uid.Name,
				"email":     uid.Email,
			})
		}
		item := map[string]any{
			"fingerprint": k.Fingerprint,
			"algorithm": map[string]any{
				"code": k.Algorithm,
			},
			"creation": time.Unix(k.Creation, 0).UTC().Format(time.RFC3339),
			"userIDs":  uids,
		}
		if k.Expiration > 0 {
			item["expiration"] = time.Unix(k.Expiration, 0).UTC().Format(time.RFC3339)
		}
		out = append(out, item)
	}
	return out, nil
}
