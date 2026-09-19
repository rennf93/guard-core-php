<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Support;

final class Text
{
    private const WHITESPACE = [
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
        0x85, 0xa0, 0x1680, 0x2000, 0x2001, 0x2002, 0x2003, 0x2004,
        0x2005, 0x2006, 0x2007, 0x2008, 0x2009, 0x200a, 0x2028, 0x2029,
        0x202f, 0x205f, 0x3000,
    ];

    public static function len(string $s): int
    {
        return mb_strlen($s, 'UTF-8');
    }

    public static function slice(string $s, int $start, ?int $length = null): string
    {
        return mb_substr($s, $start, $length ?? null, 'UTF-8');
    }

    public static function bytesToCp(string $s, int $byteOffset): int
    {
        if ($byteOffset <= 0) {
            return 0;
        }

        return mb_strlen(mb_strcut($s, 0, $byteOffset, 'UTF-8'), 'UTF-8');
    }

    public static function ordAt(string $s, int $cpIndex): int
    {
        return self::ord(mb_substr($s, $cpIndex, 1, 'UTF-8'));
    }

    public static function ord(string $char): int
    {
        if ($char === '') {
            return 0xfffd;
        }
        $first = ord($char[0]);
        if ($first < 0x80) {
            return $first;
        }
        $lens = [0xf0 => 4, 0xe0 => 3, 0xc0 => 2];
        $len = 0;
        foreach ($lens as $mask => $n) {
            if (($first & $mask) === $mask && $n > 1) {
                $len = $n;
                break;
            }
        }
        if ($len === 0) {
            return 0xfffd;
        }
        $masks = [2 => 0x1f, 3 => 0x0f, 4 => 0x07];
        $cp = $first & $masks[$len];
        for ($i = 1; $i < $len; $i++) {
            if ($i >= strlen($char) || (ord($char[$i]) & 0xc0) !== 0x80) {
                return 0xfffd;
            }
            $cp = ($cp << 6) | (ord($char[$i]) & 0x3f);
        }

        return $cp;
    }

    public static function chr(int $cp): string
    {
        if ($cp >= 0xd800 && $cp <= 0xdfff) {
            $cp = 0xfffd;
        }

        return mb_chr($cp, 'UTF-8');
    }

    public static function isspaceCp(int $cp): bool
    {
        return in_array($cp, self::WHITESPACE, true);
    }

    public static function isspace(string $char): bool
    {
        return self::isspaceCp(self::ord($char));
    }

    public static function isprintableCp(int $cp): bool
    {
        if ($cp === 0x20) {
            return true;
        }
        if ($cp < 0x20 || ($cp >= 0x7f && $cp <= 0x9f)) {
            return false;
        }
        $nonPrintable = [
            0xa0, 0xad, 0x1680, 0x2000, 0x2001, 0x2002, 0x2003, 0x2004,
            0x2005, 0x2006, 0x2007, 0x2008, 0x2009, 0x200a, 0x200b, 0x200c,
            0x200d, 0x200e, 0x200f, 0x2028, 0x2029, 0x202a, 0x202b, 0x202c,
            0x202d, 0x202e, 0x202f, 0x205f, 0x2060, 0xfeff, 0x3000,
        ];

        return !in_array($cp, $nonPrintable, true);
    }

    public static function cpBytes(int $cp): string
    {
        if ($cp < 0x80) {
            return chr($cp);
        }
        if ($cp < 0x800) {
            return chr(0xc0 | ($cp >> 6)) . chr(0x80 | ($cp & 0x3f));
        }
        if ($cp < 0x10000) {
            return chr(0xe0 | ($cp >> 12)) . chr(0x80 | (($cp >> 6) & 0x3f)) . chr(0x80 | ($cp & 0x3f));
        }

        return chr(0xf0 | ($cp >> 18)) . chr(0x80 | (($cp >> 12) & 0x3f)) . chr(0x80 | (($cp >> 6) & 0x3f)) . chr(0x80 | ($cp & 0x3f));
    }
}
