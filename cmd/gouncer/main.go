// Command gouncer runs the gateway from a JSON config file.
//
//	gouncer [config.json]   (default: gouncer.json)
//
// Example gouncer.json:
//
//	{
//	  "addr": ":4000",
//	  "rate_per_minute": 120,
//	  "routes": {
//	    "planner": {"upstream": "http://127.0.0.1:11435", "model_as": "qwen2.5-coder"},
//	    "coder":   {"upstream": "http://127.0.0.1:11436"}
//	  }
//	}
package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/t0ul/gouncer"
)

type fileConfig struct {
	Addr            string                   `json:"addr"`
	Path            string                   `json:"path"`
	MaxBodyBytes    int64                    `json:"max_body_bytes"`
	MaxConcurrent   int                      `json:"max_concurrent"`
	RatePerMinute   float64                  `json:"rate_per_minute"`
	RateBurst       float64                  `json:"rate_burst"`
	UpstreamTimeout string                   `json:"upstream_timeout"`
	Routes          map[string]gouncer.Route `json:"routes"`
}

// stderrAuditor is a tiny built-in sink so the CLI is useful standalone; wire a
// *gledger.AuditLog here for a tamper-evident, redacting audit trail.
type stderrAuditor struct{}

func (stderrAuditor) Emit(traceID, span, event string, fields map[string]any) string {
	b, _ := json.Marshal(map[string]any{
		"trace_id": traceID, "span": span, "event": event, "fields": fields,
	})
	log.Println(string(b))
	return ""
}

func main() {
	path := "gouncer.json"
	if len(os.Args) > 1 {
		path = os.Args[1]
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("gouncer: read config %s: %v", path, err)
	}
	var fc fileConfig
	if err := json.Unmarshal(raw, &fc); err != nil {
		log.Fatalf("gouncer: parse config: %v", err)
	}

	cfg := gouncer.Config{
		Routes:        fc.Routes,
		Path:          fc.Path,
		MaxBodyBytes:  fc.MaxBodyBytes,
		MaxConcurrent: fc.MaxConcurrent,
		RatePerMinute: fc.RatePerMinute,
		RateBurst:     fc.RateBurst,
	}
	if fc.UpstreamTimeout != "" {
		if d, err := time.ParseDuration(fc.UpstreamTimeout); err == nil {
			cfg.UpstreamTimeout = d
		}
	}

	gw, err := gouncer.New(cfg, gouncer.WithAuditor(stderrAuditor{}))
	if err != nil {
		log.Fatal(err)
	}

	addr := fc.Addr
	if addr == "" {
		addr = envOr("GOUNCER_ADDR", ":4000")
	}
	srv := &http.Server{Addr: addr, Handler: gw, ReadHeaderTimeout: 10 * time.Second}
	log.Printf("gouncer listening on %s (%d routes)", addr, len(fc.Routes))
	log.Fatal(srv.ListenAndServe())
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
