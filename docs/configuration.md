# Configuration

`SecurityConfig` is built through a single constructor of named arguments
(every field nullable with an engine default). Arguments belonging to features
this port does not implement, when set to an enabling value, throw
`UnsupportedFeatureError` (fail closed): geo country blocking, CORS, guard
agent telemetry, and dynamic rules.

## Client identity and proxy trust

| Argument | Default | Notes |
|---|---|---|
| `trustedProxies` | `[]` | IPs or CIDRs whose forwarding headers are trusted |
| `trustedProxyDepth` | `1` | Must be >= 1 |
| `trustXForwardedProto` | `false` | Honor `X-Forwarded-Proto` for HTTPS detection |

## Access lists

| Argument | Notes |
|---|---|
| `whitelist` | IPs or CIDRs, validated at config time |
| `blacklist` | IPs or CIDRs, validated at config time |
| `excludePaths` | Paths skipped by the pipeline (defaults: `/docs`, `/redoc`, `/openapi.json`, `/openapi.yaml`, `/favicon.ico`, `/static`) |
| `emergencyMode` / `emergencyWhitelist` | Blocks everything except the whitelist |

## Redis

| Argument | Default | Notes |
|---|---|---|
| `enableRedis` | `true` | Required for distributed bans and rate limits |
| `redisUrl` | `redis://localhost:6379` | Kept for parity; the connection uses `REDIS_HOST` / `REDIS_PORT` |
| `redisPrefix` | `guard_core:` | Key prefix |
| `redisFailOpen` | `false` | On Redis failure, allow traffic instead of blocking |

## IP banning

| Argument | Default | Notes |
|---|---|---|
| `enableIpBanning` | `true` | |
| `autoBanThreshold` | `10` | Violations before an auto-ban; must be >= 1 |
| `autoBanDuration` | `3600` | Auto-ban length in seconds |
| `threatBanConfig` | `[]` | Per-category `['threshold' => .., 'duration' => ..]` overrides |
| `enableRateLimitAutoBan` | `false` | Count rate-limit violations toward auto-ban |

## Rate limiting

| Argument | Default | Notes |
|---|---|---|
| `enableRateLimiting` | `true` | |
| `rateLimit` | `10` | Requests per window |
| `rateLimitWindow` | `60` | Window length in seconds |
| `endpointRateLimits` | `[]` | Exact-path overrides, e.g. `['/api' => ['limit' => 5, 'window' => 60]]` |

## Penetration detection

| Argument | Default | Notes |
|---|---|---|
| `enablePenetrationDetection` | `true` | |
| `enabledDetectionCategories` | all 19 categories | `xss`, `sqli`, `cmd_injection`, `path_traversal`, and more |
| `detectionSemanticThreshold` | `0.7` | Semantic model threshold, in `[0.0, 1.0]` |
| `logSensitiveHeaders` | `[]` | Headers skipped by detection scanning and redacted from logs; use for the address headers (`host`, `x-forwarded-for`, ...) until a dedicated detection-exclusion knob lands |

## Cloud provider blocking, user agents, auth

| Argument | Notes |
|---|---|
| `blockCloudProviders` | Selectors `AWS` or `AWS:!us-east-1` for a region carve-out; unknown names rejected |
| `cloudIpRefreshInterval` | Seconds, clamped to `[60, 86400]` |
| `blockedUserAgents` | Regex patterns, validated at config time |
| `authVerifier` | `Closure(object $request, string $credential): mixed` used by auth-required routes |

## Logging

| Argument | Default | Notes |
|---|---|---|
| `logRequestLevel` | `null` (off) | One of `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL` |
| `logSuspiciousLevel` | `WARNING` | |
| `mutedCheckLogs` | `[]` | Check names whose logs are suppressed |
| `logSensitiveHeaders` / `logSensitiveParams` / `logSensitiveBodyFields` | `[]` | Values redacted from logs and skipped by detection scanning (headers) |

## Custom behavior

| Argument | Notes |
|---|---|
| `customErrorResponses` | Map of int status code to body message, used for every block verdict except 429 in this port |
| `onBlock` | Telemetry hook, see [Usage](usage.md) |
| `customRequestCheck` | Final user-defined gate; a non-null response blocks |
| `passiveMode` | Log violations without blocking |
| `failSecure` | Default `true`; fail-closed on unresolvable client identity and internal errors |
| `routeResolutionStrict` | Reject requests whose route cannot be resolved |

Config values are immutable; `with(['rate_limit' => 20])` returns a copy with
a bumped revision so the pipeline rebuilds its checks.
