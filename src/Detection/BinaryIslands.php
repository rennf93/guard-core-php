<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Detection;

/**
 * Binary island reduction (guard-core upstream commit 5f399234, port of
 * guard_core/detection_engine/binary_islands.py).
 *
 * A multipart file-part payload whose binary artifact characters fill at
 * least a fifth of it is reduced to its printable runs before pattern
 * scanning, so compressed upload bytes stop producing attack-shaped matches
 * while text genuinely embedded in an upload still scans in full.
 *
 * String model: the Python engine runs over surrogateescape-decoded text,
 * where every invalid byte is a lone surrogate in U+DC80-U+DCFF. This port
 * scans UTF-8 PHP strings with the same strict-decode model as
 * BinaryPrefix::build: an invalid byte is one code point decoded to U+FFFD,
 * which is outside the printable-run class and breaks runs exactly where
 * Python's lone surrogates do.
 */
final class BinaryIslands
{
    /** Artifact share at or above which a value counts as binary-like. */
    public const BINARY_LIKE_ARTIFACT_RATIO = 0.2;

    public static function valueIsBinaryLike(string $content): bool
    {
        if ($content === '') {
            return false;
        }
        $artifacts = 0;
        $chars = 0;
        $n = strlen($content);
        $i = 0;
        while ($i < $n) {
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
                $cp = 0xfffd;
                $size = 1;
            }
            if ($size === 2 && $cp < 0x80) {
                $cp = 0xfffd;
            }
            if ($size === 3 && ($cp < 0x800 || ($cp >= 0xd800 && $cp <= 0xdfff))) {
                $cp = 0xfffd;
            }
            if ($size === 4 && ($cp < 0x10000 || $cp > 0x10ffff)) {
                $cp = 0xfffd;
            }
            if (BinaryPrefix::isBinaryArtifactCp($cp)) {
                $artifacts++;
            }
            $chars++;
            $i += $size;
        }

        return $chars > 0 && $artifacts / $chars >= self::BINARY_LIKE_ARTIFACT_RATIO;
    }

    /**
     * Printable runs of at least $minRunLength characters. Runs may contain
     * tab, newline and carriage return; every other code point outside the
     * run class breaks the run. A threshold of 1 or less returns the whole
     * content, mirroring the Python helper.
     *
     * @return list<string>
     */
    public static function extractBinaryIslands(string $content, int $minRunLength): array
    {
        if ($minRunLength <= 1) {
            return [$content];
        }
        $islands = [];
        $n = strlen($content);
        $i = 0;
        $runStart = 0;
        $runLength = 0;
        while ($i < $n) {
            [$cp, $size] = self::decodeCp($content, $i, $n);
            if (self::isRunCp($cp)) {
                if ($runLength === 0) {
                    $runStart = $i;
                }
                $runLength++;
            } elseif ($runLength > 0) {
                if ($runLength >= $minRunLength) {
                    $islands[] = substr($content, $runStart, $i - $runStart);
                }
                $runLength = 0;
            }
            $i += $size;
        }
        if ($runLength >= $minRunLength) {
            $islands[] = substr($content, $runStart, $n - $runStart);
        }

        return $islands;
    }

    /**
     * The printable-run class of Python's _ISLAND_RUN_RE: tab, newline,
     * carriage return, ASCII printables, and the wide Unicode text ranges
     * excluding surrogates (invalid bytes), the replacement character and
     * the non-printable Latin-1 block.
     */
    private static function isRunCp(int $cp): bool
    {
        if ($cp === 0x09 || $cp === 0x0a || $cp === 0x0d) {
            return true;
        }
        if ($cp >= 0x20 && $cp <= 0x7e) {
            return true;
        }
        if ($cp >= 0xa1 && $cp <= 0xd7ff) {
            return true;
        }
        if ($cp >= 0xe000 && $cp <= 0xfffc) {
            return true;
        }
        if ($cp >= 0xfffe && $cp <= 0x10ffff) {
            return true;
        }

        return false;
    }

    /**
     * @return array{int, int} code point, byte size
     */
    private static function decodeCp(string $content, int $i, int $n): array
    {
        $byte = ord($content[$i]);
        if ($byte < 0x80) {
            return [$byte, 1];
        }
        if (($byte >= 0xc2 && $byte <= 0xdf) && self::isContinuation($content, $i + 1, $n)) {
            $cp = (($byte & 0x1f) << 6) | (ord($content[$i + 1]) & 0x3f);
            if ($cp >= 0x80) {
                return [$cp, 2];
            }

            return [0xfffd, 2];
        }
        if (($byte >= 0xe0 && $byte <= 0xef) && self::isContinuation($content, $i + 1, $n) && self::isContinuation($content, $i + 2, $n)) {
            $cp = (($byte & 0x0f) << 12) | ((ord($content[$i + 1]) & 0x3f) << 6) | (ord($content[$i + 2]) & 0x3f);
            if ($cp >= 0x800 && ($cp < 0xd800 || $cp > 0xdfff)) {
                return [$cp, 3];
            }

            return [0xfffd, 3];
        }
        if (($byte >= 0xf0 && $byte <= 0xf4) && self::isContinuation($content, $i + 1, $n) && self::isContinuation($content, $i + 2, $n) && self::isContinuation($content, $i + 3, $n)) {
            $cp = (($byte & 0x07) << 18) | ((ord($content[$i + 1]) & 0x3f) << 12) | ((ord($content[$i + 2]) & 0x3f) << 6) | (ord($content[$i + 3]) & 0x3f);
            if ($cp >= 0x10000 && $cp <= 0x10ffff) {
                return [$cp, 4];
            }

            return [0xfffd, 4];
        }

        return [0xfffd, 1];
    }

    private static function isContinuation(string $content, int $i, int $n): bool
    {
        return $i < $n
            && ($byte = ord($content[$i])) >= 0x80
            && $byte <= 0xbf;
    }
}
