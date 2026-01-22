package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStaticHandler(t *testing.T) {
	handler := StaticHandler()
	assert.NotNil(t, handler)
}

func TestStaticHandler_ServeRoot(t *testing.T) {
	handler := StaticHandler()

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// Should serve index.html
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Header().Get("Content-Type"), "text/html")
}

func TestStaticHandler_ServeIndexHTML(t *testing.T) {
	handler := StaticHandler()

	req := httptest.NewRequest("GET", "/index.html", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Header().Get("Content-Type"), "text/html")
}

func TestStaticHandler_ServeCSS(t *testing.T) {
	handler := StaticHandler()

	// Look for actual CSS file in static directory
	req := httptest.NewRequest("GET", "/assets/index-KAVITblg.css", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Header().Get("Content-Type"), "text/css")
}

func TestStaticHandler_ServeJS(t *testing.T) {
	handler := StaticHandler()

	// Look for actual JS file in static directory
	req := httptest.NewRequest("GET", "/assets/index-CauYGJby.js", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Header().Get("Content-Type"), "application/javascript")
}

func TestStaticHandler_ServeSVG(t *testing.T) {
	handler := StaticHandler()

	req := httptest.NewRequest("GET", "/favicon.svg", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Header().Get("Content-Type"), "image/svg+xml")
}

func TestStaticHandler_SPAFallback(t *testing.T) {
	handler := StaticHandler()

	// Path without extension should fall back to index.html for SPA routing
	req := httptest.NewRequest("GET", "/some/spa/route", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// SPA routing falls back to index.html for non-file paths
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Header().Get("Content-Type"), "text/html")
}

func TestStaticHandler_NonExistentFile(t *testing.T) {
	handler := StaticHandler()

	// Request for a file that doesn't exist but has an extension
	// Should try to serve it, fail, then fall back to index.html
	req := httptest.NewRequest("GET", "/nonexistent-file.png", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// Falls back to index.html for SPA routing
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestStaticHandler_ContentTypeHeaders(t *testing.T) {
	handler := StaticHandler()

	tests := []struct {
		path        string
		contentType string
	}{
		{"/", "text/html"},
		{"/index.html", "text/html"},
		{"/assets/index-KAVITblg.css", "text/css"},
		{"/assets/index-CauYGJby.js", "application/javascript"},
		{"/favicon.svg", "image/svg+xml"},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			req := httptest.NewRequest("GET", tt.path, nil)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			assert.Contains(t, w.Header().Get("Content-Type"), tt.contentType)
		})
	}
}

func TestStaticHandler_TrimPrefix(t *testing.T) {
	handler := StaticHandler()

	// Test that leading slashes are properly trimmed
	req := httptest.NewRequest("GET", "/favicon.svg", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.True(t, strings.Contains(w.Body.String(), "<svg") || w.Body.Len() > 0)
}

func TestStaticHandler_EmptyPath(t *testing.T) {
	handler := StaticHandler()

	// Empty path should serve index.html
	req := httptest.NewRequest("GET", "", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestStaticHandler_NestedPath(t *testing.T) {
	handler := StaticHandler()

	// Nested path without file extension - SPA fallback
	req := httptest.NewRequest("GET", "/settings/general", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// Should serve index.html for SPA routing
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Header().Get("Content-Type"), "text/html")
}

func TestStaticHandler_QueryParams(t *testing.T) {
	handler := StaticHandler()

	// Query params should not affect file serving
	req := httptest.NewRequest("GET", "/index.html?v=1.0", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Header().Get("Content-Type"), "text/html")
}

func TestStaticHandler_PathWithTrailingSlash(t *testing.T) {
	handler := StaticHandler()

	// Path with trailing slash (no file extension) - should fallback to index
	req := httptest.NewRequest("GET", "/dashboard/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// SPA fallback to index.html
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Header().Get("Content-Type"), "text/html")
}

func TestStaticHandler_ExistingAssetPath(t *testing.T) {
	handler := StaticHandler()

	// Request the assets directory (no file extension in "assets")
	req := httptest.NewRequest("GET", "/assets", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// Should try to serve it, may fall back to index.html
	assert.Contains(t, []int{http.StatusOK, http.StatusNotFound}, w.Code)
}
