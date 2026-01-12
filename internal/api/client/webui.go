package client

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"
)

//go:embed all:static
var staticFiles embed.FS

// StaticHandler returns a handler for serving the embedded static files.
func StaticHandler() http.Handler {
	subFS, err := fs.Sub(staticFiles, "static")
	if err != nil {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "Static files not available", http.StatusNotFound)
		})
	}

	fileServer := http.FileServer(http.FS(subFS))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if path == "/" || !strings.Contains(path, ".") {
			r.URL.Path = "/index.html"
		}
		fileServer.ServeHTTP(w, r)
	})
}
