# guard-core-php
Guard Core PHP - API Security Core Engine for PHP language

## Detection limits

### Size-gated pattern family (large single-line subjects)

A family of detection patterns anchored at `\A` walks the subject one character
(or one path segment) at a time: the `etc/passwd`, `boot.ini`, `proc/self/environ`
and `var/log` line walks, the keyword-lookahead double walks, and the anchored
path-walk segment loops for `.htaccess`, `wp-admin`, `.env`, `.git`, recon path
targets and siblings (`PatternData::SIZE_GATED_PATTERN_INDICES`). PCRE2 consumes
stack proportional to the walked line, so on stock php:8.3 ini a benign
single-line subject can exhaust PCRE2 and abort detection entirely:

- `pcre.jit=1` (default): failures from ~24.5KB subjects
  (`PREG_JIT_STACKLIMIT_ERROR`) for the line-walk shapes, and from ~16.4KB for
  the segment-loop shapes once a trailing target follows ~16KB of path
  segments (`a/` repeated is the stack-densest input, floor cliff ~16392
  bytes).
- `pcre.jit=0`: failures from ~100KB subjects (`PREG_RECURSION_LIMIT_ERROR`).

Mitigation: when a view subject's first line reaches
`SusPatterns::GATED_PATTERN_MAX_SUBJECT_BYTES` (15360, 15 KiB), the preg calls
of that family are skipped for the rest of the scan (no match contribution) and
detection completes normally. The threshold sits below the ~16.4KB segment-loop
cliff and above the largest conformance corpus content (14725 bytes), so it
holds under either `pcre.jit` setting (ini-independent) and never changes
conformance behavior.

Coverage trade-off: walk and segment patterns are line-scoped, so skipping
above the gate only forgoes their coverage on very long single-line subjects
(15KB or more in one line). All other patterns still scan the full subject, and
probes in shorter lines or multiline bodies are unaffected.

