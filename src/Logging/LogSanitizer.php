<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Logging;

/**
 * Console-safe log lines (guard-core 4.0.4, upstream commit f5d53ca5, port of
 * _utils/logging_utils.py::_sanitize_for_log): every assembled log line is
 * pure printable ASCII, so emission can never depend on the console encoding.
 * Newline, carriage return and tab become \n, \r and \t; valid UTF-8 code
 * points outside printable ASCII become \uXXXX escapes; raw non-UTF-8 bytes
 * (the surrogate-escape class of the Python engine) become \xNN escapes.
 */
final class LogSanitizer
{
    public static function sanitize(string $value): string
    {
        if ($value === '') {
            return $value;
        }
        $value = str_replace(["\n", "\r", "\t"], ['\\n', '\\r', '\\t'], $value);
        $out = '';
        $len = strlen($value);
        $i = 0;
        while ($i < $len) {
            $byte = ord($value[$i]);
            if ($byte < 0x80) {
                $out .= ($byte >= 32 && $byte <= 126) ? $value[$i] : sprintf('\u%04x', $byte);
                $i++;
                continue;
            }
            $sequence = self::utf8SequenceLength($byte);
            $codePoint = 0;
            if ($sequence > 0 && self::decodeUtf8($value, $i, $sequence, $codePoint)) {
                $out .= sprintf('\u%04x', $codePoint);
                $i += $sequence;
                continue;
            }
            $out .= sprintf('\x%02x', $byte);
            $i++;
        }

        return $out;
    }

    /**
     * Length of the UTF-8 sequence starting with $byte, 0 when the byte cannot
     * start a well-formed sequence (continuation bytes, overlong leads,
     * out-of-range leads).
     */
    private static function utf8SequenceLength(int $byte): int
    {
        if ($byte >= 0xc2 && $byte <= 0xdf) {
            return 2;
        }
        if ($byte >= 0xe0 && $byte <= 0xef) {
            return 3;
        }
        if ($byte >= 0xf0 && $byte <= 0xf4) {
            return 4;
        }

        return 0;
    }

    /**
     * Decode the sequence at $offset; rejects truncated sequences, bad
     * continuations, overlong encodings, surrogates and out-of-range code
     * points (they fall back to per-byte \xNN like surrogate escapes).
     */
    private static function decodeUtf8(string $value, int $offset, int $sequence, ?int &$codePoint): bool
    {
        $len = strlen($value);
        if ($offset + $sequence > $len) {
            return false;
        }
        $cp = ord($value[$offset]) & [2 => 0x1f, 3 => 0x0f, 4 => 0x07][$sequence];
        for ($j = 1; $j < $sequence; $j++) {
            $cont = ord($value[$offset + $j]);
            if (($cont & 0xc0) !== 0x80) {
                return false;
            }
            $cp = ($cp << 6) | ($cont & 0x3f);
        }
        $min = [2 => 0x80, 3 => 0x800, 4 => 0x10000][$sequence];
        if ($cp < $min || $cp > 0x10ffff || ($cp >= 0xd800 && $cp <= 0xdfff)) {
            return false;
        }
        $codePoint = $cp;

        return true;
    }
}
