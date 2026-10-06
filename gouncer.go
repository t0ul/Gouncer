// Package gouncer is a zero-dependency security gateway for OpenAI-compatible
// LLM backends: a bouncer at the door. It allowlists logical model names (a
// caller can never steer traffic to an arbitrary upstream, so no SSRF), caps
// request bodies, limits concurrency and per-client rate, propagates a single
// trace_id end to end, and exposes Auditor/Scrubber hooks so an audit log
// (gledger) and a redactor (goflage) plug in WITHOUT gouncer importing them.
//
// The Auditor interface is intentionally identical to gledger.AuditLog.Emit,
// so a *gledger.AuditLog satisfies it as-is. Part of the fleet.
package gouncer

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Auditor receives structured audit events. *gledger.AuditLog satisfies it as-is.
type Auditor interface {
	Emit(traceID, span, event string, fields map[string]any) string
}

// Scrubber returns a redacted, log-safe copy of s (goflage can be adapted to it).
type Scrubber interface {
	Scrub(s string) string
}

// Route maps a logical model name to one concrete upstream.
type Route struct {
	Upstream string `json:"upstream"`  // base URL, e.g. "http://127.0.0.1:11435"
	ModelAs  string `json:"model_as"`  // optional: model name to send upstream (default: as requested)
	APIKey   string `json:"api_key"`   // optional: sent as "Authorization: Bearer <key>" upstream
}

// Config configures a Gateway. Routes is the allowlist: an unknown model is refused.
type Config struct {
	Routes          map[string]Route
	Path            string        // request path to accept; default "/v1/chat/completions"
	MaxBodyBytes    int64         // default 1 MiB
	MaxConcurrent   int           // default 32; <0 disables the limit
	RatePerMinute   float64       // default 120; <0 disables rate limiting
	RateBurst       float64       // default = RatePerMinute
	UpstreamTimeout time.Duration // default 60s
}

// Option configures optional, decoupled collaborators.
type Option func(*Gateway)

// WithAuditor attaches an audit sink (e.g. a *gledger.AuditLog).
func WithAuditor(a Auditor) Option { return func(g *Gateway) { g.auditor = a } }

// WithScrubber attaches a redactor used to make logged prompt previews safe.
func WithScrubber(s Scrubber) Option { return func(g *Gateway) { g.scrubber = s } }

type route struct {
	upstream *url.URL
	modelAs  string
	apiKey   string
}

// Gateway is an http.Handler that proxies allowlisted models to their upstreams.
type Gateway struct {
	path     string
	routes   map[string]route
	client   *http.Client
	maxBody  int64
	sem      chan struct{}
	limiter  *limiterSet
	auditor  Auditor
	scrubber Scrubber
}

// New validates cfg and returns a ready Gateway.
func New(cfg Config, opts ...Option) (*Gateway, error) {
	if len(cfg.Routes) == 0 {
		return nil, errors.New("gouncer: at least one route is required")
	}
	g := &Gateway{
		path:    orStr(cfg.Path, "/v1/chat/completions"),
		routes:  make(map[string]route, len(cfg.Routes)),
		maxBody: orInt64(cfg.MaxBodyBytes, 1<<20),
	}
	for name, r := range cfg.Routes {
		u, err := url.Parse(r.Upstream)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return nil, fmt.Errorf("gouncer: route %q has invalid upstream %q", name, r.Upstream)
		}
		g.routes[name] = route{upstream: u, modelAs: r.ModelAs, apiKey: r.APIKey}
	}

	timeout := cfg.UpstreamTimeout
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	g.client = &http.Client{Timeout: timeout}

	if cfg.MaxConcurrent >= 0 {
		n := cfg.MaxConcurrent
		if n == 0 {
			n = 32
		}
		g.sem = make(chan struct{}, n)
	}

	rpm := cfg.RatePerMinute
	if rpm == 0 {
		rpm = 120
	}
	if rpm > 0 {
		burst := cfg.RateBurst
		if burst <= 0 {
			burst = rpm
		}
		g.limiter = newLimiterSet(rpm/60.0, burst)
	}

	for _, o := range opts {
		o(g)
	}
	return g, nil
}

// ServeHTTP implements the gateway: validate, allowlist, forward, audit.
func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	traceID := r.Header.Get("X-Trace-Id")
	if traceID == "" {
		traceID = NewTraceID()
	}
	w.Header().Set("X-Trace-Id", traceID)

	if r.URL.Path != g.path {
		g.fail(w, traceID, http.StatusNotFound, "no such path")
		return
	}
	if r.Method != http.MethodPost {
		g.fail(w, traceID, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	client := clientKey(r)
	if g.limiter != nil && !g.limiter.allow(client) {
		g.audit(traceID, "gateway", "ratelimited", map[string]any{"client": client})
		g.fail(w, traceID, http.StatusTooManyRequests, "rate limit exceeded")
		return
	}

	if g.sem != nil {
		select {
		case g.sem <- struct{}{}:
			defer func() { <-g.sem }()
		default:
			g.fail(w, traceID, http.StatusServiceUnavailable, "gateway at capacity")
			return
		}
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, g.maxBody))
	if err != nil {
		g.fail(w, traceID, http.StatusRequestEntityTooLarge, "request body too large")
		return
	}

	model := extractModel(body)
	if model == "" {
		g.fail(w, traceID, http.StatusBadRequest, `missing "model" in request body`)
		return
	}
	rt, ok := g.routes[model]
	if !ok {
		g.audit(traceID, "gateway", "denied", map[string]any{"model": model, "client": client})
		g.fail(w, traceID, http.StatusBadRequest, "model not allowed")
		return
	}

	outBody := body
	if rt.modelAs != "" {
		outBody = rewriteModel(body, rt.modelAs)
	}

	g.audit(traceID, "gateway", "forward", map[string]any{
		"model":    model,
		"client":   client,
		"bytes":    len(body),
		"upstream": rt.upstream.Host,
		"preview":  g.preview(body),
	})

	target := *rt.upstream
	target.Path = singleJoin(target.Path, g.path)
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, target.String(), bytes.NewReader(outBody))
	if err != nil {
		g.fail(w, traceID, http.StatusInternalServerError, "bad upstream request")
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Trace-Id", traceID)
	if rt.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+rt.apiKey)
	}
	if a := r.Header.Get("Accept"); a != "" {
		req.Header.Set("Accept", a)
	}

	start := time.Now()
	resp, err := g.client.Do(req)
	if err != nil {
		g.audit(traceID, "gateway", "upstream_error", map[string]any{
			"error": err.Error(), "ms": time.Since(start).Milliseconds(),
		})
		g.fail(w, traceID, http.StatusBadGateway, "upstream unreachable")
		return
	}
	defer resp.Body.Close()

	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	n, _ := io.Copy(flushWriter{w}, resp.Body)

	g.audit(traceID, "gateway", "complete", map[string]any{
		"model": model, "status": resp.StatusCode,
		"resp_bytes": n, "ms": time.Since(start).Milliseconds(),
	})
}

func (g *Gateway) audit(traceID, span, event string, fields map[string]any) {
	if g.auditor != nil {
		g.auditor.Emit(traceID, span, event, fields)
	}
}

// preview returns a scrubbed, bounded snippet of the body, or "" when no scrubber
// is attached (never log a raw prompt by default).
func (g *Gateway) preview(body []byte) string {
	if g.scrubber == nil {
		return ""
	}
	s := string(body)
	if len(s) > 500 {
		s = s[:500]
	}
	return g.scrubber.Scrub(s)
}

func (g *Gateway) fail(w http.ResponseWriter, traceID string, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]any{"message": msg, "trace_id": traceID},
	})
}

func extractModel(body []byte) string {
	var p struct {
		Model string `json:"model"`
	}
	_ = json.Unmarshal(body, &p)
	return strings.TrimSpace(p.Model)
}

func rewriteModel(body []byte, model string) []byte {
	var m map[string]any
	if json.Unmarshal(body, &m) != nil {
		return body
	}
	m["model"] = model
	out, err := json.Marshal(m)
	if err != nil {
		return body
	}
	return out
}

func clientKey(r *http.Request) string {
	if k := r.Header.Get("X-Api-Key"); k != "" {
		return "key:" + k
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	return "ip:" + host
}

var hopHeaders = map[string]bool{
	"Connection": true, "Keep-Alive": true, "Proxy-Authenticate": true,
	"Proxy-Authorization": true, "Te": true, "Trailer": true,
	"Transfer-Encoding": true, "Upgrade": true,
}

func copyHeaders(dst, src http.Header) {
	for k, vs := range src {
		if hopHeaders[http.CanonicalHeaderKey(k)] || http.CanonicalHeaderKey(k) == "X-Trace-Id" {
			continue
		}
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
}

// flushWriter flushes after every write so SSE/streamed responses pass through live.
type flushWriter struct{ w http.ResponseWriter }

func (fw flushWriter) Write(p []byte) (int, error) {
	n, err := fw.w.Write(p)
	if f, ok := fw.w.(http.Flusher); ok {
		f.Flush()
	}
	return n, err
}

func singleJoin(base, p string) string {
	base = strings.TrimSuffix(base, "/")
	if p == "" {
		return base
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return base + p
}

// NewTraceID returns a random 128-bit hex correlation id.
func NewTraceID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func orStr(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

func orInt64(v, d int64) int64 {
	if v <= 0 {
		return d
	}
	return v
}
