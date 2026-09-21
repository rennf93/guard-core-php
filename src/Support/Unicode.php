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

    // Conjoining Hangul ranges that participate in the algorithmic
    // composition (the modern, precomposable jamo only; the Old Hangul and
    // filler jamo in between do not form syllables).
    private const HANGUL_SBASE = 0xac00;
    private const HANGUL_LBASE = 0x1100;
    private const HANGUL_VBASE = 0x1161;
    private const HANGUL_TBASE = 0x11a7;
    private const HANGUL_LCOUNT = 19;
    private const HANGUL_VCOUNT = 21;
    private const HANGUL_TCOUNT = 28;
    private const HANGUL_SCOUNT = 11172;

    public static function nfkc(string $s): string
    {
        // Fast path: WORK_RE is a single PCRE scan (C speed) over the UTF-8
        // subject for every codepoint that could change an NFKC result
        // (decomposables, combining marks, composition seconds, Hangul V/T
        // jamo). With the /u flag a return value of exactly 0 means the whole
        // subject is valid UTF-8 and matched nothing, i.e. it is already in
        // NFKC form and can be returned byte-for-byte. False (invalid UTF-8)
        // and 1 (match) fall through to the general path.
        if (preg_match(UnicodeData::WORK_RE, $s) === 0) {
            return $s;
        }

        // General path. Decode UTF-8 leniently into codepoints with the same
        // grouping the previous mb_strlen/mb_substr based implementation
        // observed: each failed sequence prefix (lead byte plus any valid
        // continuation bytes before the failure) becomes one character, which
        // mbstring surfaces as the substitute character.
        $decomp = UnicodeData::NFKC_DECOMP;
        $cps = [];
        $n = strlen($s);
        $i = 0;
        while ($i < $n) {
            $b = ord($s[$i]);
            if ($b < 0x80) {
                $cps[] = $b;
                $i++;
                continue;
            }
            if ($b >= 0xc2 && $b <= 0xdf) {
                $need = 2;
                $min2 = 0x80;
                $max2 = 0xbf;
            } elseif ($b >= 0xe0 && $b <= 0xef) {
                $need = 3;
                if ($b === 0xe0) {
                    $min2 = 0xa0;
                    $max2 = 0xbf;
                } elseif ($b === 0xed) {
                    $min2 = 0x80;
                    $max2 = 0x9f;
                } else {
                    $min2 = 0x80;
                    $max2 = 0xbf;
                }
            } elseif ($b >= 0xf0 && $b <= 0xf4) {
                $need = 4;
                if ($b === 0xf0) {
                    $min2 = 0x90;
                    $max2 = 0xbf;
                } elseif ($b === 0xf4) {
                    $min2 = 0x80;
                    $max2 = 0x8f;
                } else {
                    $min2 = 0x80;
                    $max2 = 0xbf;
                }
            } else {
                $cps[] = self::substituteCp();
                $i++;
                continue;
            }
            $j = $i + 1;
            $k = 1;
            while ($k < $need) {
                if ($j >= $n) {
                    break;
                }
                $c = ord($s[$j]);
                if ($k === 1) {
                    if ($c < $min2 || $c > $max2) {
                        break;
                    }
                } elseif ($c < 0x80 || $c > 0xbf) {
                    break;
                }
                $j++;
                $k++;
            }
            if ($k === $need) {
                $cp = $b & ($need === 2 ? 0x1f : ($need === 3 ? 0x0f : 0x07));
                for ($x = $i + 1; $x < $j; $x++) {
                    $cp = ($cp << 6) | (ord($s[$x]) & 0x3f);
                }
                $cps[] = $cp;
                $i = $j;
            } else {
                $cps[] = self::substituteCp();
                $i = $j;
            }
        }

        return self::compose(self::reorder(self::decompose($cps, $decomp)));
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

    private static function substituteCp(): int
    {
        static $cp = null;
        if ($cp === null) {
            // Mirror the lenient mb_* decoder this class previously relied
            // on: it surfaces each invalid UTF-8 sequence as mbstring's
            // substitute character (by default '?'). Resolving it through
            // mb_substr keeps that behavior environment-accurate, including
            // Text::ord's U+FFFD fallback when no substitution is emitted.
            $cp = Text::ord(mb_substr("\x80", 0, 1, 'UTF-8'));
        }

        return $cp;
    }

    /**
     * @param list<int> $cps
     * @param array<int, list<int>> $decomp
     * @return list<int>
     */
    private static function decompose(array $cps, array $decomp): array
    {
        $out = [];
        foreach ($cps as $cp) {
            $d = $decomp[$cp] ?? null;
            if ($d !== null) {
                foreach ($d as $c) {
                    $out[] = $c;
                }
            } elseif ($cp >= self::HANGUL_SBASE && $cp < self::HANGUL_SBASE + self::HANGUL_SCOUNT) {
                $sIndex = $cp - self::HANGUL_SBASE;
                $out[] = self::HANGUL_LBASE + intdiv($sIndex, self::HANGUL_VCOUNT * self::HANGUL_TCOUNT);
                $out[] = self::HANGUL_VBASE + intdiv($sIndex % (self::HANGUL_VCOUNT * self::HANGUL_TCOUNT), self::HANGUL_TCOUNT);
                $t = $sIndex % self::HANGUL_TCOUNT;
                if ($t !== 0) {
                    $out[] = self::HANGUL_TBASE + $t;
                }
            } else {
                $out[] = $cp;
            }
        }

        return $out;
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

    /**
     * Canonical ordering: stable sort of each run of combining marks by
     * combining class (UAX #15). Runs never cross starters, and equal classes
     * keep their original order. Short runs insertion-sort in place; long runs
     * (an adversarial body of nothing but marks) fall back to a stable sort so
     * the pass stays O(n log n) instead of O(n^2).
     *
     * @param list<int> $cps
     * @return list<int>
     */
    private static function reorder(array $cps): array
    {
        $n = count($cps);
        if ($n < 2) {
            return $cps;
        }
        $ccs = [];
        foreach ($cps as $cp) {
            $ccs[] = self::ccc($cp);
        }
        $i = 0;
        while ($i < $n) {
            if ($ccs[$i] === 0) {
                $i++;
                continue;
            }
            $j = $i;
            while ($j < $n && $ccs[$j] !== 0) {
                $j++;
            }
            if ($j - $i <= 48) {
                for ($a = $i + 1; $a < $j; $a++) {
                    $cp = $cps[$a];
                    $cc = $ccs[$a];
                    $b = $a;
                    while ($b > $i && $ccs[$b - 1] > $cc) {
                        $cps[$b] = $cps[$b - 1];
                        $ccs[$b] = $ccs[$b - 1];
                        $b--;
                    }
                    $cps[$b] = $cp;
                    $ccs[$b] = $cc;
                }
            } else {
                $idxs = range($i, $j - 1);
                usort($idxs, static fn (int $p, int $q): int => $ccs[$p] <=> $ccs[$q]);
                $sortedCp = [];
                $sortedCc = [];
                foreach ($idxs as $p) {
                    $sortedCp[] = $cps[$p];
                    $sortedCc[] = $ccs[$p];
                }
                array_splice($cps, $i, $j - $i, $sortedCp);
                array_splice($ccs, $i, $j - $i, $sortedCc);
            }
            $i = $j;
        }

        return $cps;
    }

    /**
     * Canonical composition (UAX #15). A character composes with the pending
     * starter unless blocked by a previous character with combining class
     * greater than or equal to its own (or by any starter in between, which
     * resets the pending starter). Composition results are always starters,
     * so the starter's class stays 0 after an absorption.
     *
     * @param list<int> $cps
     */
    private static function compose(array $cps): string
    {
        $n = count($cps);
        if ($n >= 2) {
            $ccs = [];
            foreach ($cps as $cp) {
                $ccs[] = self::ccc($cp);
            }
            $starterPos = -1;
            $starterCp = 0;
            $lastCc = -1;
            for ($i = 0; $i < $n; $i++) {
                $cp = $cps[$i];
                $cc = $ccs[$i];
                if ($starterPos >= 0 && ($lastCc === 0 || $cc > $lastCc)) {
                    $composite = self::pairCompose($starterCp, $cp);
                    if ($composite !== 0) {
                        $cps[$starterPos] = $composite;
                        $starterCp = $composite;
                        $cps[$i] = -1;
                        continue;
                    }
                }
                if ($cc === 0 || $starterPos < 0) {
                    $starterPos = $i;
                    $starterCp = $cp;
                }
                $lastCc = $cc;
            }
        }
        $out = '';
        foreach ($cps as $cp) {
            if ($cp >= 0) {
                $out .= Text::cpBytes($cp);
            }
        }

        return $out;
    }

    private static function pairCompose(int $a, int $b): int
    {
        if ($a >= self::HANGUL_LBASE && $a < self::HANGUL_LBASE + self::HANGUL_LCOUNT && $b >= self::HANGUL_VBASE && $b < self::HANGUL_VBASE + self::HANGUL_VCOUNT) {
            return self::HANGUL_SBASE + ((($a - self::HANGUL_LBASE) * self::HANGUL_VCOUNT) + ($b - self::HANGUL_VBASE)) * self::HANGUL_TCOUNT;
        }
        if ($a >= self::HANGUL_SBASE && $a < self::HANGUL_SBASE + self::HANGUL_SCOUNT && ($a - self::HANGUL_SBASE) % self::HANGUL_TCOUNT === 0 && $b > self::HANGUL_TBASE && $b < self::HANGUL_TBASE + self::HANGUL_TCOUNT) {
            return $a + ($b - self::HANGUL_TBASE);
        }

        return UnicodeData::COMP[$a][$b] ?? 0;
    }
}
