package client

import (
	"embed"
	"io/fs"
	"log/slog"
	"mime"
	"net/http"
	"path"
	"strings"
)

//go:embed all:static
var staticFiles embed.FS

func init() {
	// Ensure modern font + image MIME types are registered. Go's default
	// mime.TypeByExtension table is OS-dependent and on minimal Alpine
	// images (the Bifrost container base) may be missing entries like
	// .woff2 / .woff / .ico — those then fall back to
	// "application/octet-stream", which browsers reject when paired with
	// our X-Content-Type-Options: nosniff header. Symptom: fonts silently
	// drop back to system serif. Register the right types up-front.
	for ext, ct := range map[string]string{
		".woff2":       "font/woff2",
		".woff":        "font/woff",
		".ttf":         "font/ttf",
		".otf":         "font/otf",
		".ico":         "image/x-icon",
		".webp":        "image/webp",
		".webmanifest": "application/manifest+json",
	} {
		if err := mime.AddExtensionType(ext, ct); err != nil {
			slog.Warn("register mime type", "ext", ext, "error", err)
		}
	}
}

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
		urlPath := strings.TrimPrefix(r.URL.Path, "/")

		// SPA support: navigation routes (no file extension) render index.html.
		// Concrete asset requests (with an extension: .js/.css/.woff2/...) must
		// NOT fall back to index.html — serving HTML for an asset together with
		// our X-Content-Type-Options: nosniff header makes the browser reject
		// it, so e.g. fonts silently drop to a system serif behind reverse
		// proxies. Missing assets return a clean 404 instead.
		isAsset := strings.Contains(path.Base(urlPath), ".")
		if urlPath == "" || !isAsset {
			urlPath = "index.html"
		}

		// Read and serve the file directly to avoid redirect issues
		content, err := fs.ReadFile(subFS, urlPath)
		if err != nil {
			if isAsset {
				http.NotFound(w, r)
				return
			}
			// Navigation route: fall back to index.html for client-side routing.
			content, err = fs.ReadFile(subFS, "index.html")
			if err != nil {
				http.NotFound(w, r)
				return
			}
			urlPath = "index.html"
		}

		// Pick MIME from the file extension. mime.TypeByExtension covers
		// .html/.css/.js/.json/.svg/.png/.woff2 etc. via the OS table
		// plus our init() additions. Fall back to octet-stream for
		// truly unknown extensions.
		contentType := mime.TypeByExtension(path.Ext(urlPath))
		if contentType == "" {
			contentType = "application/octet-stream"
		}

		w.Header().Set("Content-Type", contentType)
		_, _ = w.Write(content) //nolint:errcheck // Best effort static file write
	})
}
