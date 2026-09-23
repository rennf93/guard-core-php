<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Detection;

/**
 * Binary noise gate (guard-core 4.0.3 parity, upstream commit 436d6f72).
 *
 * Random binary content (zip uploads, multipart file parts) decodes to text
 * dense in "artifact" characters and reliably trips a small frozen registry of
 * low-specificity shell-source heuristics, blocking and auto-banning real
 * binary uploads. Matches from those noise-prone patterns, and only those, are
 * discarded when the window on each side of the match holds 4 or more artifact
 * characters. Signature patterns are never gated.
 *
 * String model: the Python engine scans surrogateescape-decoded text and its
 * artifact classes are evaluated over decoded code points, including the
 * surrogateescape range U+DC80-U+DCFF. This port scans UTF-8 PHP strings:
 * invalid bytes decode to U+FFFD (the Unicode replacement character), which
 * belongs to the Python artifact class, and U+DC80-U+DCFF is covered
 * explicitly, so artifact density on real binary bytes matches Python. The
 * prefix is indexed by byte offset because the engine's match spans are byte
 * offsets (PREG_OFFSET_CAPTURE); artifact characters on binary content are
 * single code points, so the 64-unit byte window tracks Python's 64-code-point
 * window there, and on sparse-artifact text the gate does not fire either way.
 */
final class BinaryPrefix
{
    public const DENSITY_RADIUS = 64;
    public const DENSITY_LIMIT = 4;

    /**
     * Artifact code point classes, mirroring _BINARY_ARTIFACT_RE from
     * guard_core/detection_engine/binary_prefix.py: control characters other
     * than tab, newline and carriage return, DEL, the Latin-1/Latin-Ext-A
     * artifact bytes outside the small text allowlist, surrogateescape bytes,
     * and the Unicode replacement character.
     */
    public static function isBinaryArtifactCp(int $cp): bool
    {
        if ($cp <= 0x7f) {
            return ($cp <= 0x08)
                || $cp === 0x0b || $cp === 0x0c
                || ($cp >= 0x0e && $cp <= 0x1f)
                || $cp === 0x7f;
        }

        return ($cp >= 0x80 && $cp <= 0xa2)
            || $cp === 0xa4
            || ($cp >= 0xa6 && $cp <= 0xa9)
            || ($cp >= 0xab && $cp <= 0xaf)
            || $cp === 0xb4
            || ($cp >= 0xb6 && $cp <= 0xb8)
            || ($cp >= 0xbb && $cp <= 0xbf)
            || ($cp >= 0x180 && $cp <= 0x24f)
            || $cp === 0xfffd
            || ($cp >= 0xdc80 && $cp <= 0xdcff);
    }

    /**
     * O(n) single pass over the scanned string, built once per scanned string
     * (per detection view), not once per match. Returns a byte-indexed array
     * where prefix[$b] counts artifact code points among the code points that
     * start before byte offset $b. Invalid bytes decode to U+FFFD, one code
     * point per byte, mirroring how the mbstring-based Text helpers count them.
     *
     * @return array<int, int>
     */
    public static function build(string $content): array
    {
        $n = strlen($content);
        $prefix = [];
        $prefix[0] = 0;
        $count = 0;
        $i = 0;
        while ($i < $n) {
            $start = $i;
            $byte = ord($content[$i]);
            if ($byte < 0x80) {
                $cp = $byte;
                $size = 1;
            } elseif (($byte >= 0xc2 && $byte <= 0xdf) && self::isContinuation($content, $i + 1, $n)) {
                $cp = (($byte & 0x1f) << 6) | (ord($content[$i + 1]) & 0x3f);
                $size = 2;
            } elseif (($byte >= 0xe0 && $byte <= 0xef) && self::isContinuation($content, $i + 1, $n) && self::isContinuation($content, $i + 2, $n)) {
                $cp = (($byte & 0x0f) << 12) | ((ord($content[$i + 1]) & 0x3f) << 6) | (ord($content[$i + 2]) & 0x3f);
                $size = 3;
            } elseif (($byte >= 0xf0 && $byte <= 0xf4) && self::isContinuation($content, $i + 1, $n) && self::isContinuation($content, $i + 2, $n) && self::isContinuation($content, $i + 3, $n)) {
                $cp = (($byte & 0x07) << 18) | ((ord($content[$i + 1]) & 0x3f) << 12) | ((ord($content[$i + 2]) & 0x3f) << 6) | (ord($content[$i + 3]) & 0x3f);
                $size = 4;
            } else {
                // Invalid byte: one code point, decoded as U+FFFD.
                $cp = 0xfffd;
                $size = 1;
            }
            // Reject overlong, surrogate and out-of-range encodings the same
            // way strict UTF-8 decoding does: they are artifact code points.
            if ($size === 2 && $cp < 0x80) {
                $cp = 0xfffd;
            }
            if ($size === 3 && ($cp < 0x800 || ($cp >= 0xd800 && $cp <= 0xdfff))) {
                $cp = 0xfffd;
            }
            if ($size === 4 && ($cp < 0x10000 || $cp > 0x10ffff)) {
                $cp = 0xfffd;
            }
            // prefix[$b] counts artifact code points whose start byte is
            // before byte offset $b, so every byte offset inside a
            // multi-byte character carries the count of fully preceding
            // code points and the array is dense over 0..n.
            for ($b = $start; $b < $start + $size; $b++) {
                $prefix[$b] = $count;
            }
            if (self::isBinaryArtifactCp($cp)) {
                $count++;
            }
            $i += $size;
        }
        $prefix[$n] = $count;

        return $prefix;
    }

    private static function isContinuation(string $content, int $i, int $n): bool
    {
        return $i < $n
            && ($byte = ord($content[$i])) >= 0x80
            && $byte <= 0xbf;
    }

    /**
     * O(1) density query: artifact count in the window of DENSITY_RADIUS
     * units on each side of the byte span [$start, $end). A null prefix
     * disables the gate (parity with the Python binary_prefix=None path).
     *
     * @param array<int, int>|null $prefix
     */
    public static function matchIsBinaryDense(?array $prefix, int $start, int $end): bool
    {
        if ($prefix === null) {
            return false;
        }
        $last = count($prefix) - 1;
        $high = min($end + self::DENSITY_RADIUS, $last);
        $low = max($start - self::DENSITY_RADIUS, 0);

        return $prefix[$high] - $prefix[$low] >= self::DENSITY_LIMIT;
    }
}
