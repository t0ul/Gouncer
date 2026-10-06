# gouncer

A zero-dependency **security gateway** for OpenAI-compatible LLM backends — the
bouncer at the door of your model fleet. Pure Go standard library, one static
binary, no ML runtime in the request path.

Part of *the fleet* — a set of small, build-your-own Go security tools that beat
reaching for a sprawling off-the-shelf stack. gouncer is the gateway (the
Go-native answer to a Python LLM proxy); it pairs with
[`gledger`](https://github.com/t0ul/gledger) for audit and
[`goflage`](https://github.com/t0ul/goflage) for redaction.

## Why

An LLM proxy is a security boundary, not just a router. gouncer treats it that way:

- **Model allowlist, not URL passthrough.** Callers name a *logical* model; the
  gateway maps it to a configured upstream. A caller can never point traffic at
  an arbitrary host, so the classic SSRF foot-gun is gone by construction.
- **Request-body cap.** `MaxBodyBytes` bounds every request (413 past the limit).
- **Concurrency + per-client rate limits.** A bounded worker pool (503 at
  capacity) and a token-bucket limiter per client key (429 when drained).
- **One `trace_id`, end to end.** Accepted from `X-Trace-Id` or minted, echoed to
  the response, and forwarded upstream — so one request is one correlatable id
  across the whole fleet.
- **Upstream credential isolation.** The caller's `Authorization` is never
  forwarded; the gateway attaches each route's own upstream key.
- **Decoupled audit & redaction.** `Auditor` and `Scrubber` are interfaces, so
  gouncer imports neither gledger nor goflage. The `Auditor` interface is
  byte-identical to `gledger.AuditLog.Emit`, so a `*gledger.AuditLog` satisfies
  it directly. Prompt previews are logged only through an attached `Scrubber`;
  with none, nothing raw is logged.

## Library

```go
gw, err := gouncer.New(gouncer.Config{
    Routes: map[string]gouncer.Route{
        "planner": {Upstream: "http://127.0.0.1:11435", ModelAs: "qwen2.5-coder", APIKey: key},
        "coder":   {Upstream: "http://127.0.0.1:11436"},
    },
    RatePerMinute: 120,
    MaxConcurrent: 32,
},
    gouncer.WithAuditor(auditLog),   // e.g. *gledger.AuditLog
    gouncer.WithScrubber(scrubber),  // e.g. a goflage adapter
)
http.ListenAndServe(":4000", gw)
```

## CLI

```sh
go build ./cmd/gouncer
./gouncer gouncer.json   # defaults to gouncer.json; GOUNCER_ADDR overrides addr
```

```json
{
  "addr": ":4000",
  "rate_per_minute": 120,
  "routes": {
    "planner": {"upstream": "http://127.0.0.1:11435", "model_as": "qwen2.5-coder"},
    "coder":   {"upstream": "http://127.0.0.1:11436"}
  }
}
```

## Test

```sh
go test ./...
```

## Status

v0. Scope is the chat-completions path with allowlisting, limits, trace
propagation, and audit/redaction hooks. Not yet: multi-upstream load balancing,
retries/circuit-breaking, and request-schema policy enforcement.
