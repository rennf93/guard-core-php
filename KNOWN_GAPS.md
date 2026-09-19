# KNOWN_GAPS

## Milestone 2a — state core

- `banned_ips`/`banned_networks` expiry float strings: the port uses
  PHP's shortest round-trip float formatting (`var_export` with
  `serialize_precision=-1`), which matches Python `str(float)` byte-for-byte
  for all realistic epoch values (integral values render as `X.0`,
  microsecond fractions render as shortest round-trip decimals). For values
  outside normal epoch range where Python prints `1e+15`-style scientific
  notation, PHP prints `1.0E+15` (uppercase E, explicit `+`). Irrelevant for
  epoch-scale expiry values; readers parse with `float()` on both sides.
- IPv4 strings with leading zeros (`010.1.1.1`) pass through unchanged in
  both the Python reference (`ip_address` rejects them) and the port
  (`FILTER_VALIDATE_IP` rejects them) — verified equal behavior.
- Python `ipaddress` accepts zone-id syntax nuances beyond
  `<addr>%<scope>`; the port handles `<addr>%<scope>` and passes everything
  else through unchanged (parse-failure passthrough is normative, so no
  interop divergence for keys).
