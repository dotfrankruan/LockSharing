# LockSharing

An OpenPGP Keyserver implementing the [OpenPGP HTTP Keyserver Protocol (HKP)](https://datatracker.ietf.org/doc/html/draft-gallagher-openpgp-hkp).

It is designed to be lightweight, efficient, and backwards-compatible with GnuPG while also exposing the newer v2 API.

**Warning:** the HKP specification is still a draft. Use with caution.

## Features

- Legacy HKP API
  - `POST /pks/add` — submit ASCII-armored public keys.
  - `GET /pks/lookup?op=get&search=...` — retrieve armored keys by email, fingerprint, or Key ID.
  - `GET /pks/lookup?op=index&search=...` — list matching keys (HTML or machine-readable with `options=mr`).
  - `GET /pks/lookup?op=stats` — basic server statistics.
- v2 HKP API
  - `GET /pks/v2/certs/by-identity/<identity>`
  - `GET /pks/v2/certs/by-keyid/<keyid>`
  - `GET /pks/v2/certs/by-vfingerprint/<vfingerprint>`
  - `GET /pks/v2/canonical/<identity>`
  - `GET /pks/v2/index/<identity>`
  - `OPTIONS /pks/v2/<category>` — feature detection.
- SQLite-backed persistent storage.
- Simple built-in web UI at `/` for uploading and searching keys.

## Web UI

Open `http://localhost:11371/` in a browser to:

- Submit an ASCII-armored public key via a form.
- Search keys by email, fingerprint, or Key ID.
- View results with full key text and metadata.

## Requirements

- Go 1.22 or newer

## Build

```bash
go build ./...
```

## Run

```bash
./LockSharing
```

By default the server listens on `:11371` and stores data in `db.sqlite3`. You can override this:

```bash
./LockSharing -addr :8080 -db /path/to/db.sqlite3
```

## Test

```bash
go test ./...
```

## Example usage

Submit a key:

```bash
curl -X POST http://localhost:11371/pks/add \
  --data-urlencode "keytext=$(cat mykey.asc)"
```

Look it up by email:

```bash
curl "http://localhost:11371/pks/lookup?op=get&search=alice@example.com"
```

Look it up by fingerprint:

```bash
curl "http://localhost:11371/pks/lookup?op=get&search=0xAABBCCDDEEFF00112233445566778899AABBCCDD"
```

List matching keys (machine-readable):

```bash
curl "http://localhost:11371/pks/lookup?op=index&search=alice@example.com&options=mr"
```

Use the v2 API:

```bash
curl "http://localhost:11371/pks/v2/certs/by-identity/alice@example.com" \
  -H "Accept: application/pgp-keys"
```

## License

See [LICENSE](LICENSE).
