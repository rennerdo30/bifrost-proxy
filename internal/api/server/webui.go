package server

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
	// Get the static subdirectory
	subFS, err := fs.Sub(staticFiles, "static")
	if err != nil {
		// Return a simple handler if embed fails
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "Static files not available", http.StatusNotFound)
		})
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/")

		// Serve index.html for root and non-file paths (SPA support)
		if path == "" || !strings.Contains(path, ".") {
			path = "index.html"
		}

		// Read and serve the file directly to avoid redirect issues
		content, err := fs.ReadFile(subFS, path)
		if err != nil {
			// Try index.html as fallback for SPA routing
			content, err = fs.ReadFile(subFS, "index.html")
			if err != nil {
				http.NotFound(w, r)
				return
			}
			path = "index.html"
		}

		// Set content type based on extension
		contentType := "application/octet-stream"
		if strings.HasSuffix(path, ".html") {
			contentType = "text/html; charset=utf-8"
		} else if strings.HasSuffix(path, ".css") {
			contentType = "text/css; charset=utf-8"
		} else if strings.HasSuffix(path, ".js") {
			contentType = "application/javascript"
		} else if strings.HasSuffix(path, ".json") {
			contentType = "application/json"
		} else if strings.HasSuffix(path, ".png") {
			contentType = "image/png"
		} else if strings.HasSuffix(path, ".svg") {
			contentType = "image/svg+xml"
		}

		w.Header().Set("Content-Type", contentType)
		w.Write(content)
	})
}
