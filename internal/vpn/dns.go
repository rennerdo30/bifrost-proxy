package vpn

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// DNSServer is a DNS server that intercepts and resolves DNS queries.
type DNSServer struct {
	config      DNSConfig
	cache       *DNSCache
	splitEngine *SplitTunnelEngine

	server     *dns.Server
	udpConn    *net.UDPConn
	tcpListener net.Listener

	// Statistics
	totalQueries   atomic.Int64
	cacheHits      atomic.Int64
	cacheMisses    atomic.Int64
	upstreamErrors atomic.Int64

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	mu     sync.Mutex
}

// DNSServerStats contains DNS server statistics.
type DNSServerStats struct {
	TotalQueries   int64 `json:"total_queries"`
	CacheHits      int64 `json:"cache_hits"`
	CacheMisses    int64 `json:"cache_misses"`
	UpstreamErrors int64 `json:"upstream_errors"`
}

// NewDNSServer creates a new DNS server.
func NewDNSServer(config DNSConfig, cache *DNSCache, splitEngine *SplitTunnelEngine) *DNSServer {
	return &DNSServer{
		config:      config,
		cache:       cache,
		splitEngine: splitEngine,
	}
}

// Start starts the DNS server.
func (s *DNSServer) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.ctx, s.cancel = context.WithCancel(ctx)

	// Create DNS handler
	handler := dns.HandlerFunc(s.handleDNSRequest)

	// Start UDP server
	udpAddr, err := net.ResolveUDPAddr("udp", s.config.Listen)
	if err != nil {
		return fmt.Errorf("invalid listen address: %w", err)
	}

	s.udpConn, err = net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on UDP: %w", err)
	}

	s.server = &dns.Server{
		PacketConn: s.udpConn,
		Handler:    handler,
		Net:        "udp",
	}

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		if err := s.server.ActivateAndServe(); err != nil {
			if !errors.Is(err, net.ErrClosed) {
				slog.Error("DNS server error", "error", err)
			}
		}
	}()

	// Also start TCP server for larger responses
	tcpAddr, err := net.ResolveTCPAddr("tcp", s.config.Listen)
	if err == nil {
		s.tcpListener, err = net.ListenTCP("tcp", tcpAddr)
		if err == nil {
			tcpServer := &dns.Server{
				Listener: s.tcpListener,
				Handler:  handler,
				Net:      "tcp",
			}

			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				if err := tcpServer.ActivateAndServe(); err != nil {
					if !errors.Is(err, net.ErrClosed) {
						slog.Error("DNS TCP server error", "error", err)
					}
				}
			}()
		}
	}

	slog.Info("DNS server started", "listen", s.config.Listen)
	return nil
}

// Stop stops the DNS server.
func (s *DNSServer) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.cancel != nil {
		s.cancel()
	}

	if s.server != nil {
		s.server.Shutdown()
	}

	if s.udpConn != nil {
		s.udpConn.Close()
	}

	if s.tcpListener != nil {
		s.tcpListener.Close()
	}

	s.wg.Wait()

	slog.Info("DNS server stopped")
	return nil
}

// handleDNSRequest handles incoming DNS requests.
func (s *DNSServer) handleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
	s.totalQueries.Add(1)

	// Create response message
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = false
	m.RecursionAvailable = true

	// Process each question
	for _, q := range r.Question {
		domain := strings.TrimSuffix(q.Name, ".")

		slog.Debug("DNS query",
			"domain", domain,
			"type", dns.TypeToString[q.Qtype],
		)

		switch q.Qtype {
		case dns.TypeA, dns.TypeAAAA:
			s.handleAddressQuery(m, q, domain)
		default:
			// Forward other query types upstream
			s.forwardQuery(m, r)
			w.WriteMsg(m)
			return
		}
	}

	w.WriteMsg(m)
}

// handleAddressQuery handles A and AAAA queries.
func (s *DNSServer) handleAddressQuery(m *dns.Msg, q dns.Question, domain string) {
	// Check cache first
	if addrs, ok := s.cache.Get(domain); ok {
		s.cacheHits.Add(1)
		s.addAddressAnswers(m, q, domain, addrs)
		return
	}

	s.cacheMisses.Add(1)

	// Query upstream
	addrs, ttl, err := s.queryUpstream(domain, q.Qtype)
	if err != nil {
		s.upstreamErrors.Add(1)
		slog.Debug("upstream query failed",
			"domain", domain,
			"error", err,
		)
		m.SetRcode(m, dns.RcodeServerFailure)
		return
	}

	// Store in cache
	if len(addrs) > 0 {
		s.cache.Put(domain, addrs, ttl)
	}

	s.addAddressAnswers(m, q, domain, addrs)
}

// addAddressAnswers adds A or AAAA records to the response.
func (s *DNSServer) addAddressAnswers(m *dns.Msg, q dns.Question, domain string, addrs []netip.Addr) {
	for _, addr := range addrs {
		if q.Qtype == dns.TypeA && addr.Is4() {
			rr := &dns.A{
				Hdr: dns.RR_Header{
					Name:   q.Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				A: addr.AsSlice(),
			}
			m.Answer = append(m.Answer, rr)
		} else if q.Qtype == dns.TypeAAAA && addr.Is6() {
			rr := &dns.AAAA{
				Hdr: dns.RR_Header{
					Name:   q.Name,
					Rrtype: dns.TypeAAAA,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				AAAA: addr.AsSlice(),
			}
			m.Answer = append(m.Answer, rr)
		}
	}
}

// queryUpstream queries upstream DNS servers.
func (s *DNSServer) queryUpstream(domain string, qtype uint16) ([]netip.Addr, time.Duration, error) {
	if len(s.config.Upstream) == 0 {
		return nil, 0, errors.New("no upstream DNS servers configured")
	}

	// Create query message
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), qtype)
	m.RecursionDesired = true

	client := &dns.Client{
		Timeout: 5 * time.Second,
	}

	var lastErr error
	for _, upstream := range s.config.Upstream {
		// Ensure port is specified
		if !strings.Contains(upstream, ":") {
			upstream = upstream + ":53"
		}

		resp, _, err := client.Exchange(m, upstream)
		if err != nil {
			lastErr = err
			continue
		}

		if resp.Rcode != dns.RcodeSuccess {
			lastErr = fmt.Errorf("DNS error: %s", dns.RcodeToString[resp.Rcode])
			continue
		}

		// Extract addresses and TTL
		addrs := make([]netip.Addr, 0)
		var ttl time.Duration = 5 * time.Minute // Default TTL

		for _, ans := range resp.Answer {
			switch rr := ans.(type) {
			case *dns.A:
				if addr, ok := netip.AddrFromSlice(rr.A); ok {
					addrs = append(addrs, addr)
					if rr.Hdr.Ttl > 0 && time.Duration(rr.Hdr.Ttl)*time.Second < ttl {
						ttl = time.Duration(rr.Hdr.Ttl) * time.Second
					}
				}
			case *dns.AAAA:
				if addr, ok := netip.AddrFromSlice(rr.AAAA); ok {
					addrs = append(addrs, addr)
					if rr.Hdr.Ttl > 0 && time.Duration(rr.Hdr.Ttl)*time.Second < ttl {
						ttl = time.Duration(rr.Hdr.Ttl) * time.Second
					}
				}
			}
		}

		return addrs, ttl, nil
	}

	if lastErr != nil {
		return nil, 0, lastErr
	}

	return nil, 0, errors.New("no response from upstream DNS servers")
}

// forwardQuery forwards a DNS query to upstream servers.
func (s *DNSServer) forwardQuery(m *dns.Msg, r *dns.Msg) {
	if len(s.config.Upstream) == 0 {
		m.SetRcode(r, dns.RcodeServerFailure)
		return
	}

	client := &dns.Client{
		Timeout: 5 * time.Second,
	}

	for _, upstream := range s.config.Upstream {
		if !strings.Contains(upstream, ":") {
			upstream = upstream + ":53"
		}

		resp, _, err := client.Exchange(r, upstream)
		if err != nil {
			continue
		}

		// Copy response
		m.Answer = resp.Answer
		m.Ns = resp.Ns
		m.Extra = resp.Extra
		m.Rcode = resp.Rcode
		return
	}

	m.SetRcode(r, dns.RcodeServerFailure)
}

// Resolve resolves a domain name to IP addresses.
func (s *DNSServer) Resolve(domain string) ([]netip.Addr, error) {
	// Check cache first
	if addrs, ok := s.cache.Get(domain); ok {
		return addrs, nil
	}

	// Query upstream for both A and AAAA
	addrsV4, ttlV4, err4 := s.queryUpstream(domain, dns.TypeA)
	addrsV6, ttlV6, err6 := s.queryUpstream(domain, dns.TypeAAAA)

	if err4 != nil && err6 != nil {
		return nil, fmt.Errorf("failed to resolve %s: %v, %v", domain, err4, err6)
	}

	// Combine results
	addrs := make([]netip.Addr, 0, len(addrsV4)+len(addrsV6))
	addrs = append(addrs, addrsV4...)
	addrs = append(addrs, addrsV6...)

	// Cache with minimum TTL
	ttl := ttlV4
	if ttlV6 < ttl && ttlV6 > 0 {
		ttl = ttlV6
	}
	if len(addrs) > 0 {
		s.cache.Put(domain, addrs, ttl)
	}

	return addrs, nil
}

// Stats returns DNS server statistics.
func (s *DNSServer) Stats() DNSServerStats {
	return DNSServerStats{
		TotalQueries:   s.totalQueries.Load(),
		CacheHits:      s.cacheHits.Load(),
		CacheMisses:    s.cacheMisses.Load(),
		UpstreamErrors: s.upstreamErrors.Load(),
	}
}

// CacheEntries returns all DNS cache entries.
func (s *DNSServer) CacheEntries() []DNSCacheEntry {
	if s.cache == nil {
		return nil
	}
	return s.cache.Entries()
}

// ClearCache clears the DNS cache.
func (s *DNSServer) ClearCache() {
	if s.cache != nil {
		s.cache.Clear()
	}
}
