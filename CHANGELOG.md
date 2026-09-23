# Release Notes

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
