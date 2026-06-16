package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultPageHandler_Root(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	defaultPageHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("/ got %d, want 200", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "HolePunched") {
		t.Error("body missing HolePunched")
	}
	if !strings.Contains(body, "data:image/png;base64,") {
		t.Error("body missing embedded logo")
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type: %s", ct)
	}
}

func TestDefaultPageHandler_NonRoot404(t *testing.T) {
	for _, p := range []string{"/foo", "/favicon.ico", "/robots.txt"} {
		req := httptest.NewRequest("GET", p, nil)
		w := httptest.NewRecorder()
		defaultPageHandler(w, req)
		if w.Code != http.StatusNotFound {
			t.Errorf("%s got %d, want 404", p, w.Code)
		}
	}
}

func TestNoListDir_FileServed(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "index.html"), []byte("<h1>hi</h1>"), 0644)

	fs := http.FileServer(noListDir{http.Dir(dir)})
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	fs.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("index.html got %d, want 200", w.Code)
	}
}

func TestNoListDir_NoIndexBlocked(t *testing.T) {
	dir := t.TempDir()
	// Directory exists but has no index.html
	os.Mkdir(filepath.Join(dir, "subdir"), 0755)

	fs := http.FileServer(noListDir{http.Dir(dir)})

	// Root directory without index.html → 404
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	fs.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("bare dir got %d, want 404", w.Code)
	}
}

func TestNoListDir_SubdirWithIndex(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "index.html"), []byte("root"), 0644)
	sub := filepath.Join(dir, "sub")
	os.Mkdir(sub, 0755)
	os.WriteFile(filepath.Join(sub, "index.html"), []byte("sub"), 0644)

	fs := http.FileServer(noListDir{http.Dir(dir)})

	req := httptest.NewRequest("GET", "/sub/", nil)
	w := httptest.NewRecorder()
	fs.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("subdir with index got %d, want 200", w.Code)
	}
}

func TestNoListDir_SubdirNoIndexBlocked(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "index.html"), []byte("root"), 0644)
	os.Mkdir(filepath.Join(dir, "noindex"), 0755)

	fs := http.FileServer(noListDir{http.Dir(dir)})
	req := httptest.NewRequest("GET", "/noindex/", nil)
	w := httptest.NewRecorder()
	fs.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("subdir without index got %d, want 404", w.Code)
	}
}
