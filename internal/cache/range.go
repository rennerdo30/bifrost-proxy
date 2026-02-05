package cache

import (
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/textproto"
	"strconv"
	"strings"
)

// RangeSpec represents a parsed Range request specification.
type RangeSpec struct {
	Ranges []ByteRange
}

// ByteRange represents a single byte range.
type ByteRange struct {
	Start int64
	End   int64
}

// Length returns the number of bytes in this range.
func (r ByteRange) Length() int64 {
	return r.End - r.Start + 1
}

// ContentRange returns the Content-Range header value for this range.
func (r ByteRange) ContentRange(total int64) string {
	return fmt.Sprintf("bytes %d-%d/%d", r.Start, r.End, total)
}

// ParseRangeSpec parses an HTTP Range header.
// Returns nil if the header is empty or invalid.
func ParseRangeSpec(header string, size int64) (*RangeSpec, error) {
	if header == "" {
		return nil, nil
	}

	if !strings.HasPrefix(header, "bytes=") {
		return nil, errors.New("invalid range unit")
	}

	rangeStr := strings.TrimPrefix(header, "bytes=")
	if rangeStr == "" {
		return nil, errors.New("empty range specification")
	}

	parts := strings.Split(rangeStr, ",")
	ranges := make([]ByteRange, 0, len(parts))

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		r, err := parseSingleRange(part, size)
		if err != nil {
			continue // Skip invalid ranges
		}

		ranges = append(ranges, r)
	}

	if len(ranges) == 0 {
		return nil, errors.New("no valid ranges")
	}

	return &RangeSpec{Ranges: ranges}, nil
}

// parseSingleRange parses a single range specification.
func parseSingleRange(spec string, size int64) (ByteRange, error) {
	dashIdx := strings.Index(spec, "-")
	if dashIdx < 0 {
		return ByteRange{}, errors.New("missing dash in range")
	}

	startStr := spec[:dashIdx]
	endStr := spec[dashIdx+1:]

	var start, end int64
	var err error

	if startStr == "" {
		// Suffix range: "-500" means last 500 bytes
		suffixLen, parseErr := strconv.ParseInt(endStr, 10, 64)
		if parseErr != nil {
			return ByteRange{}, fmt.Errorf("invalid suffix length: %w", parseErr)
		}
		if suffixLen <= 0 {
			return ByteRange{}, errors.New("suffix length must be positive")
		}
		start = size - suffixLen
		if start < 0 {
			start = 0
		}
		end = size - 1
	} else if endStr == "" {
		// Open-ended range: "500-" means byte 500 to end
		start, err = strconv.ParseInt(startStr, 10, 64)
		if err != nil {
			return ByteRange{}, fmt.Errorf("invalid start: %w", err)
		}
		end = size - 1
	} else {
		// Full range: "500-999"
		start, err = strconv.ParseInt(startStr, 10, 64)
		if err != nil {
			return ByteRange{}, fmt.Errorf("invalid start: %w", err)
		}
		end, err = strconv.ParseInt(endStr, 10, 64)
		if err != nil {
			return ByteRange{}, fmt.Errorf("invalid end: %w", err)
		}
	}

	// Validate range
	if start < 0 {
		return ByteRange{}, errors.New("start must be non-negative")
	}
	if start > end {
		return ByteRange{}, errors.New("start must be <= end")
	}
	if start >= size {
		return ByteRange{}, errors.New("start exceeds content length")
	}

	// Clamp end to content length
	if end >= size {
		end = size - 1
	}

	return ByteRange{Start: start, End: end}, nil
}

// IsSatisfiable checks if any of the ranges are satisfiable.
func (rs *RangeSpec) IsSatisfiable(size int64) bool {
	if rs == nil || len(rs.Ranges) == 0 {
		return false
	}

	for _, r := range rs.Ranges {
		if r.Start < size {
			return true
		}
	}
	return false
}

// TotalLength returns the total number of bytes covered by all ranges.
func (rs *RangeSpec) TotalLength() int64 {
	if rs == nil {
		return 0
	}

	var total int64
	for _, r := range rs.Ranges {
		total += r.Length()
	}
	return total
}

// IsSingleRange returns true if there's exactly one range.
func (rs *RangeSpec) IsSingleRange() bool {
	return rs != nil && len(rs.Ranges) == 1
}

// RangeReader wraps a ReadSeeker to read a specific byte range.
type RangeReader struct {
	reader    io.ReadSeeker
	start     int64
	end       int64
	remaining int64
}

// NewRangeReader creates a reader for a specific byte range.
func NewRangeReader(reader io.ReadSeeker, start, end int64) (*RangeReader, error) {
	if _, err := reader.Seek(start, io.SeekStart); err != nil {
		return nil, fmt.Errorf("failed to seek to range start: %w", err)
	}

	return &RangeReader{
		reader:    reader,
		start:     start,
		end:       end,
		remaining: end - start + 1,
	}, nil
}

// Read implements io.Reader.
func (r *RangeReader) Read(p []byte) (n int, err error) {
	if r.remaining <= 0 {
		return 0, io.EOF
	}

	if int64(len(p)) > r.remaining {
		p = p[:r.remaining]
	}

	n, err = r.reader.Read(p)
	r.remaining -= int64(n)

	if r.remaining <= 0 && err == nil {
		err = io.EOF
	}

	return n, err
}

// MultipartRangeWriter writes multiple ranges as multipart MIME.
type MultipartRangeWriter struct {
	writer      io.Writer
	multiWriter *multipart.Writer
	contentType string
	size        int64
}

// NewMultipartRangeWriter creates a writer for multipart range responses.
func NewMultipartRangeWriter(w io.Writer, contentType string, size int64) *MultipartRangeWriter {
	mw := multipart.NewWriter(w)
	return &MultipartRangeWriter{
		writer:      w,
		multiWriter: mw,
		contentType: contentType,
		size:        size,
	}
}

// Boundary returns the MIME boundary string.
func (w *MultipartRangeWriter) Boundary() string {
	return w.multiWriter.Boundary()
}

// ContentType returns the full Content-Type header value.
func (w *MultipartRangeWriter) ContentType() string {
	return fmt.Sprintf("multipart/byteranges; boundary=%s", w.multiWriter.Boundary())
}

// WritePart writes a single range part.
func (w *MultipartRangeWriter) WritePart(r ByteRange, data []byte) error {
	h := make(textproto.MIMEHeader)
	h.Set("Content-Type", w.contentType)
	h.Set("Content-Range", r.ContentRange(w.size))

	part, err := w.multiWriter.CreatePart(h)
	if err != nil {
		return fmt.Errorf("failed to create part: %w", err)
	}

	if _, err := part.Write(data); err != nil {
		return fmt.Errorf("failed to write part: %w", err)
	}

	return nil
}

// Close finishes the multipart message.
func (w *MultipartRangeWriter) Close() error {
	return w.multiWriter.Close()
}

// CoalesceRanges merges overlapping or adjacent ranges.
func CoalesceRanges(ranges []ByteRange) []ByteRange {
	if len(ranges) <= 1 {
		return ranges
	}

	// Sort by start position (simple bubble sort for small slices)
	for i := range ranges {
		for j := i + 1; j < len(ranges); j++ {
			if ranges[j].Start < ranges[i].Start {
				ranges[i], ranges[j] = ranges[j], ranges[i]
			}
		}
	}

	// Merge overlapping/adjacent ranges
	result := make([]ByteRange, 0, len(ranges))
	current := ranges[0] //nolint:gosec // G602: False positive - len(ranges) > 1 is checked at line 267

	for i := 1; i < len(ranges); i++ {
		if ranges[i].Start <= current.End+1 {
			// Overlapping or adjacent - extend current range
			if ranges[i].End > current.End {
				current.End = ranges[i].End
			}
		} else {
			// Gap - emit current and start new
			result = append(result, current)
			current = ranges[i]
		}
	}
	result = append(result, current)

	return result
}

// UnsatisfiableRangeError represents a 416 Range Not Satisfiable error.
type UnsatisfiableRangeError struct {
	Size int64
}

func (e *UnsatisfiableRangeError) Error() string {
	return fmt.Sprintf("range not satisfiable, content length: %d", e.Size)
}

// ContentRangeHeader returns the Content-Range header for 416 responses.
func (e *UnsatisfiableRangeError) ContentRangeHeader() string {
	return fmt.Sprintf("bytes */%d", e.Size)
}
