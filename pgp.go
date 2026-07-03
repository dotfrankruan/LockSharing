package main

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
)

// UIDInfo holds the parsed User ID metadata.
type UIDInfo struct {
	Name    string
	Email   string
	Revoked bool
	Expired bool
}

// KeyInfo holds the parsed metadata for a single public key.
type KeyInfo struct {
	Fingerprint string
	KeyID       string
	Algorithm   int
	BitLength   int
	Creation    int64
	Expiration  int64
	UIDs        []UIDInfo
	Revoked     bool
	Expired     bool
	Keytext     string
}

var emailRe = regexp.MustCompile(`<([^>]+)>`)

// parseKeytext parses an ASCII-armored certificate bundle and returns
// metadata for each certificate it contains.
func parseKeytext(keytext string) ([]KeyInfo, error) {
	el, err := openpgp.ReadArmoredKeyRing(strings.NewReader(keytext))
	if err != nil {
		return nil, fmt.Errorf("invalid key data: %w", err)
	}

	now := time.Now()
	var infos []KeyInfo
	for _, e := range el {
		info, err := entityToKeyInfo(e, now)
		if err != nil {
			return nil, err
		}
		info.Keytext = serializeEntityArmor(e)
		infos = append(infos, info)
	}
	return infos, nil
}

func entityToKeyInfo(e *openpgp.Entity, now time.Time) (KeyInfo, error) {
	pk := e.PrimaryKey
	if pk == nil {
		return KeyInfo{}, fmt.Errorf("missing primary key")
	}

	bits, _ := pk.BitLength()
	creation := pk.CreationTime.Unix()
	expiration := int64(0)

	selfSig := e.SelfSignature
	if selfSig == nil {
		for _, id := range e.Identities {
			if id.SelfSignature != nil {
				selfSig = id.SelfSignature
				break
			}
		}
	}
	if selfSig != nil && selfSig.KeyLifetimeSecs != nil {
		expiration = pk.CreationTime.Add(time.Duration(*selfSig.KeyLifetimeSecs) * time.Second).Unix()
	}

	info := KeyInfo{
		Fingerprint: strings.ToUpper(fmt.Sprintf("%X", pk.Fingerprint)),
		KeyID:       fmt.Sprintf("%016X", pk.KeyId),
		Algorithm:   int(pk.PubKeyAlgo),
		BitLength:   int(bits),
		Creation:    creation,
		Expiration:  expiration,
		Revoked:     len(e.Revocations) > 0,
		Expired:     expiration > 0 && expiration < now.Unix(),
	}

	for name, id := range e.Identities {
		email := ""
		if m := emailRe.FindStringSubmatch(name); len(m) > 1 {
			email = m[1]
		}
		uidExpired := false
		if id.SelfSignature != nil && id.SelfSignature.SigLifetimeSecs != nil {
			exp := id.SelfSignature.CreationTime.Add(time.Duration(*id.SelfSignature.SigLifetimeSecs) * time.Second)
			uidExpired = exp.Before(now)
		}
		info.UIDs = append(info.UIDs, UIDInfo{
			Name:    name,
			Email:   email,
			Revoked: len(id.Revocations) > 0,
			Expired: uidExpired,
		})
	}

	return info, nil
}

func serializeEntityArmor(e *openpgp.Entity) string {
	var buf bytes.Buffer
	w, err := armor.Encode(&buf, openpgp.PublicKeyType, nil)
	if err != nil {
		return ""
	}
	_ = e.Serialize(w)
	_ = w.Close()
	return buf.String()
}

func serializeArmoredBundle(entities []*openpgp.Entity) string {
	var buf bytes.Buffer
	for _, e := range entities {
		buf.WriteString(serializeEntityArmor(e))
		buf.WriteByte('\n')
	}
	return buf.String()
}

func serializeBinaryBundle(entities []*openpgp.Entity) ([]byte, error) {
	var buf bytes.Buffer
	for _, e := range entities {
		if err := e.Serialize(&buf); err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}

// parseEntities parses stored armored keytexts back into openpgp entities.
func parseEntities(keytexts []string) ([]*openpgp.Entity, error) {
	var entities []*openpgp.Entity
	for _, kt := range keytexts {
		el, err := openpgp.ReadArmoredKeyRing(strings.NewReader(kt))
		if err != nil {
			return nil, err
		}
		entities = append(entities, el...)
	}
	return entities, nil
}

// armorBundle wraps already-parsed entities into a single armored block.
func armorBundle(entities []*openpgp.Entity) (string, error) {
	var buf bytes.Buffer
	w, err := armor.Encode(&buf, openpgp.PublicKeyType, nil)
	if err != nil {
		return "", err
	}
	for _, e := range entities {
		if err := e.Serialize(w); err != nil {
			_ = w.Close()
			return "", err
		}
	}
	if err := w.Close(); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// fingerprintVersion returns the OpenPGP fingerprint version byte for the
// given fingerprint string ("04" for v4, "06" for v6, etc.).
func fingerprintVersion(fp string) string {
	if len(fp) == 40 {
		return "04"
	}
	if len(fp) == 64 {
		return "06"
	}
	return ""
}

// normalizeHex removes a leading "0x" and upper-cases the input.
func normalizeHex(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	return strings.ToUpper(s)
}

func isHex(s string) bool {
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return len(s) > 0
}
