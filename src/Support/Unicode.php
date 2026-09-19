<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Support;

use RenzoFranceschini\GuardCore\Support\Generated\UnicodeData;

final class Unicode
{
    private const LOOKALIKES = [
        0x2044 => '/', 0xff0f => '/', 0x29f8 => '/', 0x0130 => 'I', 0x0131 => 'i',
        0x200b => '', 0x200c => '', 0x200d => '', 0xfeff => '', 0xad => '',
        0x34f => '', 0x180e => '', 0x2028 => "\n", 0x2029 => "\n", 0xe000 => '',
        0xfff0 => '', 0x1c0 => '|', 0x37e => ';', 0x2215 => '/', 0x2216 => '\\',
        0xff1c => '<', 0xff1e => '>', 0xff1b => ';', 0xff5c => '|', 0xff06 => '&',
    ];

    public static function nfkc(string $s): string
    {
        $out = '';
        $n = Text::len($s);
        for ($i = 0; $i < $n; $i++) {
            $char = Text::slice($s, $i, 1);
            $cp = Text::ord($char);
            $expansion = UnicodeData::NFD[$cp] ?? [$cp];
            foreach ($expansion as $c) {
                $out .= Text::cpBytes($c);
            }
        }

        return self::compose(self::reorder($out));
    }

    private static function ccc(int $cp): int
    {
        $lo = 0;
        $hi = count(UnicodeData::CCC) - 1;
        while ($lo <= $hi) {
            $mid = ($lo + $hi) >> 1;
            [$a, $b, $v] = UnicodeData::CCC[$mid];
            if ($cp < $a) {
                $hi = $mid - 1;
            } elseif ($cp > $b) {
                $lo = $mid + 1;
            } else {
                return $v;
            }
        }

        return 0;
    }

    private static function reorder(string $s): string
    {
        $n = Text::len($s);
        if ($n < 2) {
            return $s;
        }
        $chars = [];
        for ($i = 0; $i < $n; $i++) {
            $chars[] = Text::slice($s, $i, 1);
        }
        for ($i = 1; $i < $n; $i++) {
            $j = $i;
            while ($j > 0) {
                $a = self::ccc(Text::ord($chars[$j - 1]));
                $b = self::ccc(Text::ord($chars[$j]));
                if ($a === 0 || $a <= $b) {
                    break;
                }
                $tmp = $chars[$j - 1];
                $chars[$j - 1] = $chars[$j];
                $chars[$j] = $tmp;
                $j--;
            }
        }

        return implode('', $chars);
    }

    private static function compose(string $s): string
    {
        $n = Text::len($s);
        if ($n < 2) {
            return $s;
        }
        $chars = [];
        $codes = [];
        for ($i = 0; $i < $n; $i++) {
            $c = Text::slice($s, $i, 1);
            $chars[] = $c;
            $codes[] = Text::ord($c);
        }
        $starterPos = -1;
        $starterCode = -1;
        $lastClass = 0;
        for ($i = 0; $i < $n; $i++) {
            $cp = $codes[$i];
            $cls = self::ccc($cp);
            if ($starterPos >= 0 && $cls !== 0) {
                $key = $starterCode . '_' . $cp;
                $composite = UnicodeData::COMP[$key] ?? null;
                $blocked = $cls <= $lastClass;
                if ($composite !== null && !$blocked) {
                    $chars[$starterPos] = Text::cpBytes($composite);
                    $codes[$starterPos] = $composite;
                    $chars[$i] = null;
                    continue;
                }
            }
            if ($cls === 0 || $starterPos < 0) {
                $starterPos = $i;
                $starterCode = $cp;
            }
            $lastClass = $cls;
        }
        $out = '';
        foreach ($chars as $c) {
            if ($c !== null) {
                $out .= $c;
            }
        }

        return $out;
    }

    public static function normalize(string $content): string
    {
        $normalized = self::nfkc($content);
        foreach (self::LOOKALIKES as $cp => $replacement) {
            $needle = Text::cpBytes($cp);
            if ($replacement === '') {
                $normalized = str_replace($needle, '', $normalized);
            } else {
                $normalized = str_replace($needle, $replacement, $normalized);
            }
        }

        return $normalized;
    }
}
