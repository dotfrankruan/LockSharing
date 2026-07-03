package main

import (
	"bytes"
	"html/template"
	"net/http"
	"strings"
)

// uiHTML is the main web UI template.
const uiHTML = `<!doctype html>
<html lang="en">
<head>
	<meta charset="utf-8">
	<meta name="viewport" content="width=device-width, initial-scale=1">
	<title>LockSharing Keyserver</title>
	<style>
		:root {
			--bg: #f7f8fa;
			--card: #ffffff;
			--text: #1f2328;
			--muted: #656d76;
			--border: #d0d7de;
			--accent: #0969da;
			--accent-hover: #0550ae;
			--danger: #cf222e;
			--success: #1a7f37;
		}
		@media (prefers-color-scheme: dark) {
			:root {
				--bg: #0d1117;
				--card: #161b22;
				--text: #c9d1d9;
				--muted: #8b949e;
				--border: #30363d;
				--accent: #58a6ff;
				--accent-hover: #79c0ff;
				--danger: #f85149;
				--success: #3fb950;
			}
		}
		* { box-sizing: border-box; }
		body {
			font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
			background: var(--bg);
			color: var(--text);
			margin: 0;
			padding: 2rem 1rem;
			line-height: 1.5;
		}
		.container { max-width: 800px; margin: 0 auto; }
		header { margin-bottom: 2rem; }
		h1 { margin: 0 0 .25rem; font-size: 1.75rem; }
		.subtitle { color: var(--muted); margin: 0; }
		.card {
			background: var(--card);
			border: 1px solid var(--border);
			border-radius: .75rem;
			padding: 1.25rem;
			margin-bottom: 1.25rem;
		}
		label { display: block; margin-bottom: .35rem; font-weight: 600; }
		input[type="text"], textarea {
			width: 100%;
			padding: .6rem .75rem;
			border: 1px solid var(--border);
			border-radius: .5rem;
			background: var(--card);
			color: var(--text);
			font: inherit;
		}
		textarea { min-height: 12rem; resize: vertical; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; }
		.actions { margin-top: .75rem; display: flex; gap: .5rem; flex-wrap: wrap; }
		button {
			background: var(--accent);
			color: white;
			border: 0;
			border-radius: .5rem;
			padding: .6rem 1rem;
			font: inherit;
			cursor: pointer;
		}
		button:hover { background: var(--accent-hover); }
		.secondary { background: var(--border); color: var(--text); }
		.secondary:hover { background: var(--border); opacity: .8; }
		.alert {
			border-radius: .5rem;
			padding: .75rem 1rem;
			margin-bottom: 1rem;
		}
		.alert-success { background: rgba(26,127,55,.12); color: var(--success); }
		.alert-error { background: rgba(207,34,46,.12); color: var(--danger); }
		pre {
			background: rgba(128,128,128,.08);
			border: 1px solid var(--border);
			border-radius: .5rem;
			padding: 1rem;
			overflow-x: auto;
			white-space: pre-wrap;
			word-break: break-all;
		}
		.key-meta { color: var(--muted); font-size: .9rem; margin-bottom: .5rem; }
		.empty { color: var(--muted); text-align: center; padding: 2rem; }
		footer { margin-top: 2rem; color: var(--muted); font-size: .85rem; text-align: center; }
		.nav { display: flex; gap: 1rem; margin-bottom: 1rem; }
		.nav a { color: var(--accent); text-decoration: none; }
		.nav a:hover { text-decoration: underline; }
	</style>
</head>
<body>
	<div class="container">
		<header>
			<h1>LockSharing Keyserver</h1>
			<p class="subtitle">OpenPGP HKP keyserver with legacy and v2 API support</p>
		</header>

		{{if .Message}}
		<div class="alert alert-{{.MessageType}}">{{.Message}}</div>
		{{end}}

		<div class="card">
			<form method="post" action="/ui/upload">
				<label for="keytext">Submit a public key</label>
				<textarea id="keytext" name="keytext" placeholder="-----BEGIN PGP PUBLIC KEY BLOCK-----&#10;..." required>{{.Keytext}}</textarea>
				<div class="actions">
					<button type="submit">Submit key</button>
				</div>
			</form>
		</div>

		<div class="card">
			<form method="get" action="/ui/search">
				<label for="q">Search keys</label>
				<input type="text" id="q" name="q" value="{{.Query}}" placeholder="email, fingerprint, or key ID" required>
				<div class="actions">
					<button type="submit">Search</button>
				</div>
			</form>
		</div>

		{{if .Results}}
		<div class="card">
			<h3>Search results ({{len .Results}})</h3>
			{{range .Results}}
			<div class="key-meta">
				<strong>Fingerprint:</strong> {{.Fingerprint}} <br>
				<strong>Key ID:</strong> {{.KeyID}} <br>
				<strong>Algorithm:</strong> {{.Algorithm}} <strong>Bits:</strong> {{.BitLength}}
			</div>
			<pre>{{.Keytext}}</pre>
			{{end}}
		</div>
		{{else if .Searched}}
		<div class="card">
			<p class="empty">No keys found.</p>
		</div>
		{{end}}

		<footer>
			<a href="/pks/lookup?op=stats">Stats</a> ·
			<a href="https://datatracker.ietf.org/doc/html/draft-gallagher-openpgp-hkp">HKP draft</a>
		</footer>
	</div>
</body>
</html>
`

var uiTemplate = template.Must(template.New("ui").Parse(uiHTML))

// uiPage is the data passed to the UI template.
type uiPage struct {
	Message     string
	MessageType string
	Keytext     string
	Query       string
	Results     []StoredKey
	Searched    bool
}

func (s *Server) handleUIIndex(w http.ResponseWriter, r *http.Request) {
	renderUI(w, uiPage{})
}

func (s *Server) handleUIUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		renderUI(w, uiPage{Message: "Invalid form.", MessageType: "error"})
		return
	}
	keytext := r.PostFormValue("keytext")
	infos, err := parseKeytext(keytext)
	page := uiPage{Keytext: keytext}
	if err != nil {
		page.Message = "Could not parse key: " + err.Error()
		page.MessageType = "error"
		renderUI(w, page)
		return
	}
	var ok []string
	for _, info := range infos {
		_, err := s.db.Store(info)
		if err != nil {
			page.Message = "Database error: " + err.Error()
			page.MessageType = "error"
			renderUI(w, page)
			return
		}
		ok = append(ok, info.Fingerprint)
	}
	page.Message = "Submitted " + strings.Join(ok, ", ")
	page.MessageType = "success"
	page.Keytext = ""
	renderUI(w, page)
}

func (s *Server) handleUISearch(w http.ResponseWriter, r *http.Request) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	page := uiPage{Query: q, Searched: q != ""}
	if q == "" {
		renderUI(w, page)
		return
	}
	keys, err := s.searchKeys(q)
	if err != nil {
		page.Message = "Search error: " + err.Error()
		page.MessageType = "error"
		renderUI(w, page)
		return
	}
	page.Results = keys
	renderUI(w, page)
}

func renderUI(w http.ResponseWriter, page uiPage) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	var buf bytes.Buffer
	if err := uiTemplate.Execute(&buf, page); err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}
	_, _ = buf.WriteTo(w)
}
