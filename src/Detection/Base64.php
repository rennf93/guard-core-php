<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Detection;

use RenzoFranceschini\GuardCore\Support\Text;

final class Base64
{
    public const MIN_RUN_LENGTH = 12;
    public const GZIP_MAGIC = "\x1f\x8b";
    public const PRINTABLE_RATIO_THRESHOLD = 0.5;
    public const FALLBACK_PRINTABLE_RATIO_THRESHOLD = 0.95;
    public const MAX_REPLACEMENT_CHAR_RATIO = 0.2;
    public const MAX_GUNZIP_ATTEMPTS_PER_PASS = 8;

    public const DATA_ALPHABET = 'A-Za-z0-9+/_\-';

    public static function isHexLiteral(string $token): bool
    {
        return preg_match('/\A0[xX][0-9a-fA-F]+\z/', $token) === 1;
    }

    public static function printableRatio(string $text): float
    {
        if ($text === '') {
            return 0.0;
        }
        $n = Text::len($text);
        $printable = 0;
        for ($i = 0; $i < $n; $i++) {
            if (Text::isprintableCp(Text::ordAt($text, $i))) {
                $printable++;
            }
        }

        return $printable / $n;
    }

    public static function replacementCharRatio(string $text): float
    {
        if ($text === '') {
            return 0.0;
        }
        $n = Text::len($text);
        $count = mb_substr_count($text, "\u{FFFD}", 'UTF-8');

        return $count / $n;
    }

    public static function boundedGunzip(string $raw, int $maxOutputBytes): ?string
    {
        if (strlen($raw) < 2 || substr($raw, 0, 2) !== self::GZIP_MAGIC) {
            return null;
        }
        $out = @gzdecode($raw, $maxOutputBytes);

        return $out === false ? null : $out;
    }

    private static function decodeCleaned(string $cleaned, float $minPrintableRatio, array &$gunzipLeft, int $gunzipMax): ?string
    {
        $padding = (4 - (strlen($cleaned) % 4)) % 4;
        $padded = $cleaned . str_repeat('=', $padding);
        $raw = base64_decode($padded, true);
        if ($raw === false) {
            return null;
        }
        if (strlen($raw) >= 2 && substr($raw, 0, 2) === self::GZIP_MAGIC && $gunzipLeft > 0) {
            $gunzipLeft--;
            $gunzipped = self::boundedGunzip($raw, $gunzipMax);
            if ($gunzipped !== null) {
                $raw = $gunzipped;
            }
        }
        if (!mb_check_encoding($raw, 'UTF-8')) {
            $decoded = @mb_convert_encoding($raw, 'UTF-8', 'UTF-8');
            if ($decoded === false) {
                return null;
            }
            if (self::replacementCharRatio($decoded) > self::MAX_REPLACEMENT_CHAR_RATIO) {
                return null;
            }
        } else {
            $decoded = $raw;
        }
        if (self::printableRatio($decoded) >= $minPrintableRatio) {
            return $decoded;
        }

        return null;
    }

    private static function decodeToken(string $token, float $minPrintableRatio, array &$gunzipLeft, int $gunzipMax): ?string
    {
        if (self::isHexLiteral($token)) {
            return null;
        }
        $cleaned = self::stripSeparators($token);
        $urlsafe = strtr($cleaned, ['-' => '+', '_' => '/']);
        $decoded = self::decodeCleaned($urlsafe, $minPrintableRatio, $gunzipLeft, $gunzipMax);
        if ($decoded !== null) {
            return $decoded;
        }
        if (str_contains($cleaned, '-') || str_contains($cleaned, '_')) {
            return self::decodeCleaned(str_replace(['-', '_'], '', $cleaned), $minPrintableRatio, $gunzipLeft, $gunzipMax);
        }

        return null;
    }

    private static function stripSeparators(string $token): string
    {
        $out = '';
        $n = Text::len($token);
        for ($i = 0; $i < $n; $i++) {
            $cp = Text::ordAt($token, $i);
            if ($cp < 0x80 && (ctype_alnum(chr($cp)) || $cp === 0x2b || $cp === 0x2f || $cp === 0x2d || $cp === 0x5f)) {
                $out .= chr($cp);
            } elseif ($cp >= 0xdc80 && $cp <= 0xdcff) {
                $out .= chr($cp - 0xdc80 + 0x80);
            }
        }

        return $out;
    }

    public static function decodeCandidates(string $content, array &$gunzipLeft, int $gunzipMax): string
    {
        $dataAlphabet = self::DATA_ALPHABET;
        $sep = '[^\r\n=]|[^\x20-\x7e]';
        $runUnit = "[{$dataAlphabet}][{$sep}]*";
        $base64Re = '(?<![' . $dataAlphabet . '])(?:(?:' . $runUnit . '){' . self::MIN_RUN_LENGTH . ',}={0,2}|(?:' . $runUnit . '){' . (self::MIN_RUN_LENGTH - 1) . ',}=|(?:' . $runUnit . '){' . (self::MIN_RUN_LENGTH - 2) . ',}==)(?![' . $dataAlphabet . '=])';
        $runRe = '(?<![' . $dataAlphabet . '])[' . $dataAlphabet . ']{' . self::MIN_RUN_LENGTH . ',}={0,2}(?![' . $dataAlphabet . '=])';
        $subFloorRe = '(?<![' . $dataAlphabet . '])[' . $dataAlphabet . ']{1,' . (self::MIN_RUN_LENGTH - 1) . '}(?![' . $dataAlphabet . '])';
        $self = null;

        return Preg::replace($base64Re, $content, static function (array $m) use ($runRe, $subFloorRe, &$gunzipLeft, $gunzipMax): string {
            $token = $m['text'];
            $primaryThreshold = preg_match('/[_-]|[^\x20-\x7e\r\n=]/', $token) === 1
                ? self::FALLBACK_PRINTABLE_RATIO_THRESHOLD
                : self::PRINTABLE_RATIO_THRESHOLD;
            $decoded = self::decodeToken($token, $primaryThreshold, $gunzipLeft, $gunzipMax);
            $base = $decoded;
            if ($base === null) {
                $base = Preg::replace($runRe, $token, static function (array $rm) use (&$gunzipLeft, $gunzipMax): string {
                    $d = self::decodeToken($rm['text'], self::FALLBACK_PRINTABLE_RATIO_THRESHOLD, $gunzipLeft, $gunzipMax);

                    return $d ?? $rm['text'];
                });
            }
            $fragments = '';
            foreach (Preg::allMatches($subFloorRe, $token) as $fm) {
                $fragments .= $fm['text'];
            }
            $reassembled = null;
            if (strlen($fragments) >= self::MIN_RUN_LENGTH) {
                $reassembled = self::decodeToken($fragments, self::FALLBACK_PRINTABLE_RATIO_THRESHOLD, $gunzipLeft, $gunzipMax);
            }
            if ($reassembled === null || ($base !== null && str_contains($base, $reassembled))) {
                return $base ?? $token;
            }

            return ($base ?? '') . ' ' . $reassembled;
        });
    }

    public static function decodeShortToken(string $token): ?string
    {
        if (Text::len($token) > self::MIN_RUN_LENGTH - 1) {
            return null;
        }
        $padding = (4 - (strlen($token) % 4)) % 4;
        $raw = base64_decode($token . str_repeat('=', $padding), true);
        if ($raw === false) {
            return null;
        }
        if (!mb_check_encoding($raw, 'UTF-8')) {
            return null;
        }

        return $raw;
    }
}
