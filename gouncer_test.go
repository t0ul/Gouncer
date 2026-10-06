package gouncer_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/t0ul/gouncer"
)

type capturedAuditor struct {
	mu     sync.Mutex
	events []string
	fields []map[string]any
}

func (c *capturedAuditor) Emit(traceID, span, event string, fields map[string]any) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, event)
	c.fields = append(c.fields, fields)
	return ""
}

func (c *capturedAuditor) has(event string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, e := range c.events {
		if e == event {
			return true
		}
	}
	return false
}

func (c *capturedAuditor) fieldsFor(event string) map[string]any {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i, e := range c.events {
		if e == event {
			return c.fields[i]
		}
	}
	return nil
}

type upstreamCapture struct {
	mu    sync.Mutex
	trace string
	auth  string
	body  []byte
}

func newUpstream(cap *upstreamCapture) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		cap.mu.Lock()
		cap.trace = r.Header.Get("X-Trace-Id")
		cap.auth = r.Header.Get("Authorization")
		cap.body = b
		cap.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
}

type scrub struct{}

func (scrub) Scrub(s string) string { return strings.ReplaceAll(s, "SECRET", "<redacted>") }

func do(t *testing.T, gwURL, body string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, gwURL+"/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestForwardRewriteAuditScrub(t *testing.T) {
	cap := &upstreamCapture{}
	up := newUpstream(cap)
	defer up.Close()

	aud := &capturedAuditor{}
	gw, err := gouncer.New(gouncer.Config{
		Routes: map[string]gouncer.Route{
			"planner": {Upstream: up.URL, ModelAs: "qwen-planner", APIKey: "upstream-key"},
		},
	}, gouncer.WithAuditor(aud), gouncer.WithScrubber(scrub{}))
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(gw)
	defer srv.Close()

	resp := do(t, srv.URL, `{"model":"planner","messages":[{"role":"user","content":"SECRET hello"}]}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if resp.Header.Get("X-Trace-Id") == "" {
		t.Error("response missing X-Trace-Id")
	}

	cap.mu.Lock()
	defer cap.mu.Unlock()
	if cap.trace == "" {
		t.Error("trace id not propagated upstream")
	}
	if cap.auth != "Bearer upstream-key" {
		t.Errorf("upstream Authorization = %q", cap.auth)
	}
	if !strings.Contains(string(cap.body), "qwen-planner") {
		t.Errorf("model not rewritten upstream: %s", cap.body)
	}
	if !aud.has("forward") || !aud.has("complete") {
		t.Error("expected forward + complete audit events")
	}
	f := aud.fieldsFor("forward")
	if f == nil {
		t.Fatal("no forward event captured")
	}
	if p, _ := f["preview"].(string); strings.Contains(p, "SECRET") || !strings.Contains(p, "<redacted>") {
		t.Errorf("preview not scrubbed: %q", p)
	}
}

func TestModelNotAllowed(t *testing.T) {
	cap := &upstreamCapture{}
	up := newUpstream(cap)
	defer up.Close()
	aud := &capturedAuditor{}
	gw, _ := gouncer.New(gouncer.Config{
		Routes: map[string]gouncer.Route{"planner": {Upstream: up.URL}},
	}, gouncer.WithAuditor(aud))
	srv := httptest.NewServer(gw)
	defer srv.Close()

	resp := do(t, srv.URL, `{"model":"evil-upstream"}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
	if !aud.has("denied") {
		t.Error("expected a denied audit event")
	}
	cap.mu.Lock()
	defer cap.mu.Unlock()
	if cap.body != nil {
		t.Error("disallowed model still reached an upstream (SSRF-ish)")
	}
}

func TestBodyTooLarge(t *testing.T) {
	cap := &upstreamCapture{}
	up := newUpstream(cap)
	defer up.Close()
	gw, _ := gouncer.New(gouncer.Config{
		Routes:       map[string]gouncer.Route{"planner": {Upstream: up.URL}},
		MaxBodyBytes: 16,
	})
	srv := httptest.NewServer(gw)
	defer srv.Close()

	resp := do(t, srv.URL, `{"model":"planner","messages":"`+strings.Repeat("A", 500)+`"}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", resp.StatusCode)
	}
}

func TestRateLimit(t *testing.T) {
	cap := &upstreamCapture{}
	up := newUpstream(cap)
	defer up.Close()
	gw, _ := gouncer.New(gouncer.Config{
		Routes:        map[string]gouncer.Route{"planner": {Upstream: up.URL}},
		RatePerMinute: 1,
		RateBurst:     1,
	})
	srv := httptest.NewServer(gw)
	defer srv.Close()

	r1 := do(t, srv.URL, `{"model":"planner"}`)
	r1.Body.Close()
	if r1.StatusCode != http.StatusOK {
		t.Fatalf("first request status = %d, want 200", r1.StatusCode)
	}
	r2 := do(t, srv.URL, `{"model":"planner"}`)
	r2.Body.Close()
	if r2.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("second request status = %d, want 429", r2.StatusCode)
	}
}

func TestMethodNotAllowed(t *testing.T) {
	up := newUpstream(&upstreamCapture{})
	defer up.Close()
	gw, _ := gouncer.New(gouncer.Config{Routes: map[string]gouncer.Route{"planner": {Upstream: up.URL}}})
	srv := httptest.NewServer(gw)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/v1/chat/completions")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", resp.StatusCode)
	}
}

func TestRejectInvalidUpstream(t *testing.T) {
	if _, err := gouncer.New(gouncer.Config{
		Routes: map[string]gouncer.Route{"x": {Upstream: "not-a-url"}},
	}); err == nil {
		t.Fatal("expected New to reject an invalid upstream")
	}
}
