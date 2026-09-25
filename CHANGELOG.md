# Release Notes

Unreleased
----------

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
