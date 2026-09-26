# Release Notes

Unreleased
----------

Ordered JSON walk for bodies and embedded JSON values
-----------------------------------------------------

### Added

- **JSON-content-type request bodies now walk as ordered JSON instead of scanning as one raw blob, and query parameters, headers, and form or multipart field values that themselves parse as JSON walk leaf-first with the `:embedded_json` context suffix.** The walk mirrors the reference engine's `body_json_scan.py`/`embedded_json_scan.py` (and the Go engine's `jsonwalk.go`): insertion-ordered parse with duplicate keys keeping the first position and the last value, every object key scanned as a plain `request_body` component, mongo operator keys (`$where`, `$ne`, `$gt`, ...) reported straight from the walk as nosql hits without a pattern scan, scalar leaves scanned as `str(value)` with the plain `request_body` context on the body walk and `<original context>:embedded_json` for embedded values, string leaves that themselves parse as JSON walked again with another suffix, and objects or arrays at the depth cap (32) serialized back to compact JSON and scanned as one value. Malformed input, trailing data, scalar roots, and nesting past the decoder cap fall back to the raw blob or raw value scan. New `JsonWalk` detection class; `SuspiciousActivityCheck` consumes the forced nosql category filtered by `enabled_detection_categories`.

### Verification

- Full suite green on PHP 8.3 (Docker): the thirteen `bin/` runners plus `bin/conformance.php` (184/184 vectors, verdicts unchanged), and the new `bin/test_json_walk.php` honesty runner (48/48: parse gate, insertion order and duplicate keys, scalar renderings, mongo operator hits, depth-cap compact serialization and escaping, pipeline detection through bodies/query/headers, malformed and scalar JSON blob fallback, and recursive embedded walks), verified red on master (the runner aborts on the missing `JsonWalk` class).

Raw-view recon scan
-------------------

### Fixed

- **Backslash-prefixed recon probes such as `\default` were invisible in every configured pipeline.** The preprocessor folds LDAP hex escapes (`\de` -> `Þ`) before the pattern tables run, so a query or body value like `\default` arrived at the recon rows as `Þfault` and matched nothing, and the recon-category rows were excluded from the raw-view pattern set, so the original value was never scanned against them either. The recon rows are now additionally scanned against the signal-preserving raw view (new `PatternData::RECON_RAW_VIEW_PATTERN_SOURCES`, emitted by `tools/gen_tables.py` from the reference table; view exclusion treats them as members of both the processed scans and the raw view), the #116 leading-separator gate applies to raw-view matches unchanged (bare words stay innocent in query and body contexts, separator-prefixed probes detect again, url_path and unknown are unchanged), and a (pattern, match text) deduplication on the raw-view merge keeps a row matching both views a single threat instead of doubling the threat score, with raw-view timeout sources deduplicated the same way (parity with guard-core `fix/raw-view-recon-scan`, upstream commit 81cf07f1; mirrors the Rust engine port in guard-core-rs). This resolves the `\default` divergence pinned by `bin/test_recon_context_gate.php`, which now asserts the probe as a member of `PROBE_PATHS`.

### Verification

- Full suite green on PHP 8.3 (Docker): the eight `bin/` runners plus `bin/conformance.php` (184/184 vectors, verdicts unchanged), the new `bin/test_recon_raw_view_scan.php` honesty runner (77/77: probes detect in query_param/request_body/url_path through the configured `SuspiciousActivityCheck` pipeline, bare words stay innocent, double-view matches collapse to one, `\2fdefault` keeps single-hit decoded semantics), and `bin/test_recon_context_gate.php` at 141/141 with `\default` and `\report.asp` promoted from known divergence to probe.

Form and multipart body scanning with binary islands
----------------------------------------------------

### Added

- **The suspicious-activity scan now extracts request bodies instead of scanning them as one raw value.** Urlencoded bodies scan as field pairs (the field name as a plain `request_body` component, each value with the `request_body:form_field` context), multipart bodies parse per RFC 2046 with the reference engine's observable semantics and scan as part entries (field label plus filename, part headers, payload, each with the `request_body:multipart_field context`), and a body that declares a boundary but carries none falls back to the raw blob scan. Values that parse as embedded JSON scan leaf-first with the `:embedded_json` context suffix, so the per-context gates in the pattern builder see the context of the value actually being scanned for the first time (the suffix was consumed but never produced before).
- **Binary-dense multipart file-part payloads reduce to printable runs before pattern scanning.** A named file part whose binary artifact characters fill at least a fifth of it is reduced to printable runs of at least `detection_binary_min_run_length` (new `SecurityConfig` field, default 16, bounds [4, 1024]) scanned as individual values, so compressed or encrypted upload bytes stop producing attack-shaped matches whose rate grows with file size, while text genuinely embedded in an upload still scans in full; text uploads, short or mostly-text payloads, and whole-body fallback scans keep their full scan. New `BinaryIslands` and `BodyFormScan` detection classes mirror the reference `detection_engine/binary_islands.py` and `_utils/body_form_scan.py` (upstream commit 5f399234); the multipart parser was validated differentially against the reference engine's email parser on 481 hand-built and randomized bodies with identical parts, contexts and islands.

### Verification

- Full suite green on PHP 8.3 (Docker): the eight `bin/` runners plus `bin/conformance.php` (184/184 vectors, verdicts unchanged), and the new `bin/test_body_form_scan.php` honesty runner (41/41: island unit shapes, config bounds, form-field sqli, multipart text/binary smuggling/noise cases, the min-run-length knob, embedded JSON leaves, name and filename scanning, and exact extraction contexts), verified red on master (the runner aborts on the missing extraction classes).

Text/plain block responses, console-safe log lines, and the recon leading-separator gate
-----------------------------------------------------------------------------------------

### Fixed

- **Blocked and error responses went out with no Content-Type.** `GuardResponseFactory::createResponse` built responses with an empty header bag while the security headers carry `X-Content-Type-Options: nosniff`, so every block and error response the adapters copy verbatim (403, 400, 429, the fail-secure 500, custom error messages) went out with no Content-Type at all. Body responses now declare `text/plain; charset=utf-8`; redirects carry no body and stay header-minimal (parity with fastapi-guard #144, upstream commit 4059fbe).
- **Log lines could carry raw control and non-ASCII bytes.** `LogActivity::buildMessage` interpolated redacted-but-unsanitized header, url, reason and trigger values, making line emission depend on the console encoding. Every assembled line is now pure printable ASCII (new `LogSanitizer`, port of the Python `_sanitize_for_log`): newline, carriage return and tab use the short escapes, every other control or non-ASCII code point becomes `\uXXXX`, and raw non-UTF-8 bytes (the surrogate-escape class of the Python engine) become `\xNN` (guard-core 4.0.4 parity, upstream commit f5d53ca5).
- **Deep-nested JSON in loggable values produced raw or half-redacted output.** When the JSON display-redaction depth cap trips (parse failure at the cap or traversal past it), the whole value now collapses to `[REDACTED]` instead of falling through to XML/pair redaction of the raw text; malformed JSON keeps falling through to those fallbacks (guard-core 4.0.4 parity, upstream commit 8bae9459).
- **Recon path rows flagged bare field values such as `?system=SAP` or `?file=README.md`.** Whole-value recon rows whose leading path separator is optional now require the scanned value to live in a path-like context (`url_path` or `unknown`) or to start with a path separator: `/default.asp` style probes still detect in every context, `url_path` behavior is unchanged, and the gate is keyed on the normalized context of the value actually being scanned (parity with guard-core PR #116, upstream commit 79818055). Regenerating the frozen conformance corpus at the post-#116 engine commit is a follow-up.

### Verification

- Full suite green on PHP 8.3 (Docker): the eight `bin/` runners plus `bin/conformance.php` (184/184 vectors, verdicts unchanged), the new `bin/test_recon_context_gate.php` honesty runner (130/130), and the binary-noise gate runner (80/80).

___

v4.0.4 (2026-09-24)
-------------------

First stable release, full parity with guard-core 4.0.4 (v4.0.4)
----------------------------------------------------------------

### Added

- **Full parity with the Python guard-core 4.0.4 engine: all 17 security checks ported and passing.** The behavioral WAF engine now matches the reference engine check-for-check (route config, emergency mode, HTTPS enforcement, request logging, request size and content, required headers, authentication, referrer, custom validators, time window, cloud IP refresh, IP security, cloud provider, user agent, rate limit, suspicious activity, custom request).
- **Binary-noise gates over the detection engine, including the SQLi comment-terminator binary gate.** Noise-prone pattern matches inside binary body content are discarded before reporting, and SQLi patterns that terminate on comment-like byte sequences are explicitly gated in binary bodies, closing the last detection divergence against the reference corpus.
- **Conformance corpus harmonized to spec 4.0.3.** The fixture corpus (`tests/Conformance/`) carries the reference engine's expected values, including binary-body vectors, and must never be hand-edited.

### Changed

- **First stable release on Packagist.** The package installs as `rennf93/guard-core-php` (PHP 8.2+, platform-only dependencies: pcre, mbstring, json); the version is derived from the git tag, and this v4.0.4 tag is the first stable, non-pre-release publish. The earlier v0.1.0 tag was a burned pre-release snapshot and is superseded by this release.

### Verification

- Interop harness against the reference engine: 82/82 vectors passing.
- Full suite: the eight `bin/` runners plus `bin/conformance.php` across PHP 8.2, 8.3 and 8.4 (CI and the Release Gate workflow at the tag).

___
