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

// HandleRequest attempts to serve a request from cache.
// Returns true if the request was handled (served from cache), false if it should
// be forwarded to the backend.
func (i *Interceptor) HandleRequest(ctx context.Context, conn net.Conn, req *http.Request) (bool, error) {
	if i.manager == nil || !i.manager.IsEnabled() {
		return false, nil
	}

	// Only handle GET requests
	if req.Method != http.MethodGet {
		return false, nil
	}

	// Check if we should cache this domain
	if !i.manager.ShouldCache(req) {
		return false, nil
	}

	// Try to get from cache
	entry, err := i.manager.Get(ctx, req)
	if err != nil {
		// Cache miss - let the request proceed to backend
		return false, nil
	}
	defer entry.Close()

	// Check if entry is fresh
	if !i.validator.IsFresh(entry) {
		// Entry is stale - need to revalidate or fetch fresh
		return false, nil
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
func (i *Interceptor) serveFromCache(ctx context.Context, conn net.Conn, req *http.Request, entry *Entry) (bool, error) {
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
		return false, err
	}

	slog.Info("served from cache",
		"host", req.Host,
		"path", req.URL.Path,
		"size", meta.ContentLength,
		"age", time.Since(meta.CreatedAt).Round(time.Second),
	)

	return true, nil
}

// serveRangeRequest handles HTTP Range requests from cache.
func (i *Interceptor) serveRangeRequest(ctx context.Context, conn net.Conn, req *http.Request, entry *Entry, rangeHeader string) (bool, error) {
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
		return false, nil // Let backend handle it
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
		return false, err
	}

	slog.Info("served range from cache",
		"host", req.Host,
		"path", req.URL.Path,
		"range", fmt.Sprintf("%d-%d", r.start, r.end),
		"size", contentLength,
	)

	return true, nil
}

// StoreResponse stores an HTTP response in the cache.
// The body is read and stored, and a new reader is returned for forwarding.
func (i *Interceptor) StoreResponse(ctx context.Context, req *http.Request, resp *http.Response) (io.ReadCloser, error) {
	if i.manager == nil || !i.manager.IsEnabled() {
		return resp.Body, nil
	}

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

	var ranges []byteRange

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
		slog.Debug("failed to cache response", "error", err)
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
	w.Write(rw.body.Bytes())

	return w.Flush()
}
