# guard-core-php

Guard Core PHP is the API security core engine for PHP: a faithful port of the
Python `guard-core` engine. It contains all shared security logic and no
framework bindings.

## What it provides

- Penetration attempt detection (XSS, SQLi, command injection, path traversal,
  SSRF, NoSQL, template injection, deserialization, and more) with
  Python-engine-compatible semantics, over table-driven NFKC normalization and
  generated pattern tables
- IP banning with auto-ban thresholds and per-threat-category tuning
- Distributed rate limiting backed by Redis with endpoint-level overrides
- Cloud provider IP range blocking (AWS, GCP, Azure, DigitalOcean, Linode,
  Vultr) with region carve-outs
- Route-scoped configuration (per-route rate limits, auth, header
  requirements, custom validators)
- Redis-backed state with fail-open / fail-secure modes
- A block hook (`onBlock`) as the telemetry seam for agent wiring

## Ecosystem position

```text
guard-core-php (this repo)  <- Engine: all security logic lives here
├── psr15-guard             <- Adapter: PSR-7/PSR-15 middleware
├── slim-guard              <- Adapter: Slim 4 composition of psr15-guard
├── laravel-guard           <- Adapter: Illuminate HTTP middleware
└── symfony-guard           <- Adapter: HttpFoundation middleware
```

The engine is framework-agnostic by design: it operates on its own
`GuardRequest`/`GuardResponse` abstractions. Framework integration happens in
the adapter repositories above; each adapter translates native requests into a
`SimpleGuardRequest` (or its own `GuardRequest` implementation), runs
`GuardEngine::execute()`, and translates a non-null `GuardResponse` verdict
into a framework response.

## Installation

```bash
composer require rennf93/guard-core-php
```

Requires PHP 8.2 or later with `ext-pcre`, `ext-mbstring`, and `ext-json`.
Redis works through a built-in RESP2 client (no `ext-redis` needed).

## Quick start

```php
use RenzoFranceschini\GuardCore\Config\SecurityConfig;
use RenzoFranceschini\GuardCore\Engine\GuardEngine;
use RenzoFranceschini\GuardCore\Request\SimpleGuardRequest;

$config = new SecurityConfig(enableRedis: false);
$engine = new GuardEngine($config);
$engine->initialize();

$request = new SimpleGuardRequest(
    urlPath: '/api',
    method: 'GET',
    clientHost: '203.0.113.9',
);

$verdict = $engine->execute($request);
if ($verdict !== null) {
    // Blocked: $verdict->statusCode(), $verdict->headers(), $verdict->body()
}
```

A `null` response from `GuardEngine::execute()` means the request is allowed;
a non-null `GuardResponse` carries the block verdict (status code, headers,
body).

## Next steps

- [Usage](usage.md) - engine lifecycle, the request contract, and the managers
- [Configuration](configuration.md) - every `SecurityConfig` knob
