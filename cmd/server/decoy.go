package main

import (
	_ "embed"
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"path"
)

//go:embed assets/holepunch.png
var logoPNG []byte

// defaultPageHTML is built once at startup: the logo is inlined as a base64
// data URI so the page is self-contained with no external requests.
var defaultPageHTML = func() string {
	logo := base64.StdEncoding.EncodeToString(logoPNG)
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>HolePunch</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{
  background:#0a0a0a;
  color:#fff;
  font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
  display:flex;
  flex-direction:column;
  align-items:center;
  justify-content:center;
  min-height:100vh;
  gap:28px;
}
img{width:220px;height:220px;object-fit:contain}
h1{font-size:2.4rem;font-weight:700;letter-spacing:.02em}
h1 span{color:#cc2222}
p{color:#555;font-size:.85rem;letter-spacing:.04em}
</style>
</head>
<body>
<img src="data:image/png;base64,%s" alt="HolePunch">
<h1>You've been <span>HolePunched!</span></h1>
<p>UDP hole punching is live.</p>
</body>
</html>`, logo)
}()

// defaultPageHandler serves the "HolePunched!" splash on / and 404s everything else.
// Used when no -webroot is configured.
func defaultPageHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	fmt.Fprint(w, defaultPageHTML)
}

// noListDir wraps http.Dir and suppresses directory listings: if a directory
// contains no index.html, Open returns os.ErrNotExist so the file server
// returns 404 instead of exposing the directory tree.
type noListDir struct{ http.Dir }

func (d noListDir) Open(name string) (http.File, error) {
	f, err := d.Dir.Open(name)
	if err != nil {
		return nil, err
	}
	stat, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if stat.IsDir() {
		index, err := d.Dir.Open(path.Join(name, "index.html"))
		if err != nil {
			f.Close()
			return nil, os.ErrNotExist
		}
		index.Close()
	}
	return f, nil
}
