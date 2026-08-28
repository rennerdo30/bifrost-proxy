package cache

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Interceptor intercepts HTTP requests for caching.
type Interceptor struct {
	manager   *Manager
	validator *Validator
}

// NewInterceptor creates a new cache interceptor.
func NewInterceptor(manager *Manager) *Interceptor {
	return &Interceptor{
		manager:   manager,
		validator: NewValidator(),
	}
}

// Hit describes the outcome of an attempt to serve a request from the cache.
//
// Callers need the status code that was actually written to the client so that
// access logs and Prometheus counters attribute a cache hit to its real status
// (200, 206, or whatever status was cached) instead of falling back to a
// synthetic error status.
type Hit struct {
	// Handled reports whether a complete response was written to the
	// connection. When false the request must be forwarded to a backend.
	Handled bool
	// StatusCode is the HTTP status written to the client. It is only
	// meaningful when Handled is true.
	StatusCode int
}

// missed is the zero Hit: nothing was written, the request must go upstream.
var missed = Hit{}

// HandleRequest attempts to serve a request from cache.
// Returns true if the request was handled (served from cache), false if it should
// be forwarded to the backend.
//
// Prefer HandleRequestWithResult when the caller needs the served status code.
func (i *Interceptor) HandleRequest(ctx context.Context, conn net.Conn, req *http.Request) (bool, error) {
	hit, err := i.HandleRequestWithResult(ctx, conn, req)
	return hit.Handled, err
}

// HandleRequestWithResult attempts to serve a request from cache and reports
// both whether the request was handled and the status code written to the
// client.
func (i *Interceptor) HandleRequestWithResult(ctx context.Context, conn net.Conn, req *http.Request) (Hit, error) {
	if i.manager == nil || !i.manager.IsEnabled() {
		return missed, nil
	}

	// Only handle GET requests
	if req.Method != http.MethodGet {
		return missed, nil
	}

	// Check if we should cache this domain
	if !i.manager.ShouldCache(req) {
		return missed, nil
	}

	// Try to get from cache
	entry, err := i.manager.Get(ctx, req)
	if err != nil {
		// Cache miss - let the request proceed to backend
		return missed, nil
	}
	defer entry.Close()

	// Check if entry is fresh
	if !i.validator.IsFresh(entry) {
		// Entry is stale - need to revalidate or fetch fresh
		return missed, nil
	}

	// Handle Range requests
	rangeHeader := req.Header.Get("Range")
	if rangeHeader != "" {
		return i.serveRangeRequest(ctx, conn, req, entry, rangeHeader)
	}

	// Serve from cache
	return i.serveFromCache(ctx, conn, req, entry)
}

// serveFromCache writes a cached response to the connection.
func (i *Interceptor) serveFromCache(_ context.Context, conn net.Conn, req *http.Request, entry *Entry) (Hit, error) {
	meta := entry.Metadata

	// Build response
	resp := &http.Response{
		StatusCode:    meta.StatusCode,
		Status:        fmt.Sprintf("%d %s", meta.StatusCode, http.StatusText(meta.StatusCode)),
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        make(http.Header),
		ContentLength: meta.ContentLength,
		Body:          entry.Body,
		Request:       req,
	}

	// Copy headers from cached response
	for k, v := range meta.Headers {
		resp.Header[k] = v
	}

	// Add cache-specific headers
	resp.Header.Set("X-Cache", "HIT")
	resp.Header.Set("X-Cache-Key", truncateKey(meta.Key))
	resp.Header.Set("Age", strconv.FormatInt(int64(time.Since(meta.CreatedAt).Seconds()), 10))

	// Write response
	if err := resp.Write(conn); err != nil {
		slog.Error("failed to write cached response",
			"error", err,
			"host", req.Host,
			"path", req.URL.Path,
		)
		return missed, err
	}

	slog.Info("served from cache",
		"host", req.Host,
		"path", req.URL.Path,
		"status", meta.StatusCode,
		"size", meta.ContentLength,
		"age", time.Since(meta.CreatedAt).Round(time.Second),
	)

	return Hit{Handled: true, StatusCode: meta.StatusCode}, nil
}

// serveRangeRequest handles HTTP Range requests from cache.
func (i *Interceptor) serveRangeRequest(ctx context.Context, conn net.Conn, req *http.Request, entry *Entry, rangeHeader string) (Hit, error) {
	meta := entry.Metadata

	// Parse range header
	ranges, err := parseRangeHeader(rangeHeader, meta.ContentLength)
	if err != nil {
		// Invalid range - serve full content
		return i.serveFromCache(ctx, conn, req, entry)
	}

	if len(ranges) == 0 {
		// No valid ranges
		return i.serveFromCache(ctx, conn, req, entry)
	}

	// For simplicity, only handle single range
	if len(ranges) > 1 {
		// Multi-part ranges are complex - just serve full content
		return i.serveFromCache(ctx, conn, req, entry)
	}

	r := ranges[0]

	// Get range from storage
	rangeReader, err := i.manager.Storage().GetRange(ctx, meta.Key, r.start, r.end)
	if err != nil {
		slog.Warn("failed to get range from cache",
			"error", err,
			"key", truncateKey(meta.Key),
		)
		return missed, nil // Let backend handle it
	}
	defer rangeReader.Close()

	// Build 206 Partial Content response
	contentLength := r.end - r.start + 1
	resp := &http.Response{
		StatusCode:    http.StatusPartialContent,
		Status:        "206 Partial Content",
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        make(http.Header),
		ContentLength: contentLength,
		Body:          io.NopCloser(rangeReader),
		Request:       req,
	}

	// Set headers
	resp.Header.Set("Content-Type", meta.ContentType)
	resp.Header.Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", r.start, r.end, meta.ContentLength))
	resp.Header.Set("Accept-Ranges", "bytes")
	resp.Header.Set("X-Cache", "HIT")
	resp.Header.Set("X-Cache-Key", truncateKey(meta.Key))

	// Write response
	if err := resp.Write(conn); err != nil {
		return missed, err
	}

	slog.Info("served range from cache",
		"host", req.Host,
		"path", req.URL.Path,
		"range", fmt.Sprintf("%d-%d", r.start, r.end),
		"size", contentLength,
	)

	return Hit{Handled: true, StatusCode: http.StatusPartialContent}, nil
}

// StoreResponse stores an HTTP response in the cache.
// The body is read and stored, and a new reader is returned for forwarding.
func (i *Interceptor) StoreResponse(ctx context.Context, req *http.Request, resp *http.Response) (io.ReadCloser, error) {
	if i.manager == nil || !i.manager.IsEnabled() {
		return resp.Body, nil
	}

	// This response came from the origin, whether or not it turns out to be
	// cacheable. Recording it here (rather than only on the store path) is what
	// makes cache_bytes_served_total{source="origin"} comparable to
	// {source="cache"}, i.e. what makes the bandwidth-saved ratio meaningful.
	i.manager.RecordOriginBytes(resp.ContentLength)

	// Check if we should cache this response
	if !i.validator.ShouldCache(req, resp) {
		return resp.Body, nil
	}

	// Check if the domain matches a rule
	if !i.manager.ShouldCache(req) {
		return resp.Body, nil
	}

	// Read the body
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return nil, err
	}

	// Store in cache (in background to not block response)
	go func() {
		storeCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		bodyReader := io.NopCloser(bytes.NewReader(body))
		if err := i.manager.Put(storeCtx, req, resp, bodyReader); err != nil {
			slog.Warn("failed to store response in cache",
				"error", err,
				"host", req.Host,
				"path", req.URL.Path,
			)
		}
	}()

	// Return a new reader for the original body
	return io.NopCloser(bytes.NewReader(body)), nil
}

// byteRange represents a byte range for HTTP Range requests.
type byteRange struct {
	start int64
	end   int64
}

// parseRangeHeader parses an HTTP Range header.
// Example: "bytes=0-1023" or "bytes=500-999, 1000-1499"
func parseRangeHeader(header string, contentLength int64) ([]byteRange, error) {
	if !strings.HasPrefix(header, "bytes=") {
		return nil, fmt.Errorf("invalid range header: %s", header)
	}

	rangeSpec := strings.TrimPrefix(header, "bytes=")
	parts := strings.Split(rangeSpec, ",")

	ranges := make([]byteRange, 0, len(parts))

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		r, err := parseByteRange(part, contentLength)
		if err != nil {
			continue // Skip invalid ranges
		}

		ranges = append(ranges, r)
	}

	return ranges, nil
}

// parseByteRange parses a single byte range specification.
func parseByteRange(spec string, contentLength int64) (byteRange, error) {
	parts := strings.Split(spec, "-")
	if len(parts) != 2 {
		return byteRange{}, fmt.Errorf("invalid range spec: %s", spec)
	}

	var start, end int64
	var err error

	if parts[0] == "" {
		// Suffix range: "-500" means last 500 bytes
		end = contentLength - 1
		start, err = strconv.ParseInt(parts[1], 10, 64)
		if err != nil {
			return byteRange{}, err
		}
		start = contentLength - start
		if start < 0 {
			start = 0
		}
	} else if parts[1] == "" {
		// Prefix range: "500-" means from byte 500 to end
		start, err = strconv.ParseInt(parts[0], 10, 64)
		if err != nil {
			return byteRange{}, err
		}
		end = contentLength - 1
	} else {
		// Full range: "500-999"
		start, err = strconv.ParseInt(parts[0], 10, 64)
		if err != nil {
			return byteRange{}, err
		}
		end, err = strconv.ParseInt(parts[1], 10, 64)
		if err != nil {
			return byteRange{}, err
		}
	}

	// Validate range
	if start > end || start >= contentLength {
		return byteRange{}, fmt.Errorf("invalid range: %d-%d", start, end)
	}

	if end >= contentLength {
		end = contentLength - 1
	}

	return byteRange{start: start, end: end}, nil
}

// ResponseWriter wraps a connection for response interception.
type ResponseWriter struct {
	conn        net.Conn
	interceptor *Interceptor
	req         *http.Request
	statusCode  int
	header      http.Header
	wroteHeader bool
	body        *bytes.Buffer
}

// NewResponseWriter creates a new response writer for interception.
func (i *Interceptor) NewResponseWriter(conn net.Conn, req *http.Request) *ResponseWriter {
	return &ResponseWriter{
		conn:        conn,
		interceptor: i,
		req:         req,
		header:      make(http.Header),
		body:        &bytes.Buffer{},
	}
}

// Header returns the response headers.
func (rw *ResponseWriter) Header() http.Header {
	return rw.header
}

// WriteHeader writes the status code.
func (rw *ResponseWriter) WriteHeader(statusCode int) {
	if rw.wroteHeader {
		return
	}
	rw.statusCode = statusCode
	rw.wroteHeader = true
}

// Write writes body data.
func (rw *ResponseWriter) Write(data []byte) (int, error) {
	if !rw.wroteHeader {
		rw.WriteHeader(http.StatusOK)
	}
	return rw.body.Write(data)
}

// Flush sends the buffered response to the connection and caches if appropriate.
func (rw *ResponseWriter) Flush(ctx context.Context) error {
	// Build response for caching
	resp := &http.Response{
		StatusCode:    rw.statusCode,
		Status:        fmt.Sprintf("%d %s", rw.statusCode, http.StatusText(rw.statusCode)),
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        rw.header,
		ContentLength: int64(rw.body.Len()),
		Body:          io.NopCloser(bytes.NewReader(rw.body.Bytes())),
		Request:       rw.req,
	}

	// Store in cache
	bodyReader := io.NopCloser(bytes.NewReader(rw.body.Bytes()))
	if err := rw.interceptor.manager.Put(ctx, rw.req, resp, bodyReader); err != nil {
		// Count it and warn on the first one. At debug level this was
		// invisible: a cache that cannot write at all looks identical to a
		// cache nothing matches - a permanent 0% hit rate and no error.
		if count := rw.interceptor.manager.RecordStoreError(); count == 1 {
			slog.Warn("failed to cache response; further failures are logged at debug level",
				"error", err, "url", rw.req.URL.Redacted())
		} else {
			slog.Debug("failed to cache response", "error", err, "store_error_count", count)
		}
	}

	// Add cache miss header
	rw.header.Set("X-Cache", "MISS")

	// Write to connection
	return rw.writeToConn()
}

// writeToConn writes the buffered response to the connection.
func (rw *ResponseWriter) writeToConn() error {
	w := bufio.NewWriter(rw.conn)

	// Write status line
	fmt.Fprintf(w, "HTTP/1.1 %d %s\r\n", rw.statusCode, http.StatusText(rw.statusCode))

	// Write headers
	for k, vv := range rw.header {
		for _, v := range vv {
			fmt.Fprintf(w, "%s: %s\r\n", k, v)
		}
	}
	fmt.Fprintf(w, "\r\n")

	// Write body
	_, _ = w.Write(rw.body.Bytes()) //nolint:errcheck // Error will be returned by Flush

	return w.Flush()
}
