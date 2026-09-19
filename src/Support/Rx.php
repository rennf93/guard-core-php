<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Support;

final class Rx
{
    public static function pattern(string $source, bool $ignoreCase = true): string
    {
        $delim = str_contains($source, "\x01") ? "\x02" : "\x01";
        $flags = 'u' . ($ignoreCase ? 'i' : '');

        return $delim . $source . $delim . $flags;
    }

    public static function matches(string $source, string $subject, bool $ignoreCase = true): array
    {
        $matches = [];
        $ok = @preg_match_all(self::pattern($source, $ignoreCase), $subject, $matches, PREG_OFFSET_CAPTURE);

        if ($ok === false || $ok === 0) {
            return [];
        }

        $out = [];
        foreach ($matches[0] as $i => [$text, $byteStart]) {
            $byteEnd = $byteStart + strlen($text);
            $base = Text::bytesToCp($subject, $byteStart);
            $groups = [];
            foreach ($matches as $gi => $group) {
                if ($gi === 0 || !isset($group[$i])) {
                    continue;
                }
                [$gtext, $gstart] = $group[$i];
                $groups[$gi] = $gstart < 0 ? null : $gtext;
            }
            $out[] = new CMatch(
                $subject,
                $source,
                $base,
                $base + Text::len($text),
                $text,
                $groups,
            );
        }

        return $out;
    }

    public static function matchAt(string $source, string $subject, int $byteStart, int $byteEnd, bool $ignoreCase = true): ?CMatch
    {
        $segment = $byteEnd >= strlen($subject) ? substr($subject, $byteStart) : substr($subject, $byteStart, $byteEnd - $byteStart);
        if ($segment === false || $segment === '') {
            return null;
        }

        $m = [];
        $anchored = '\\A(?:' . $source . ')';
        $ok = @preg_match(self::pattern($anchored, $ignoreCase), $segment, $m, PREG_OFFSET_CAPTURE);

        if ($ok !== 1) {
            return null;
        }

        [$text, $relStart] = $m[0];
        $base = Text::bytesToCp($subject, $byteStart);
        $groups = [];
        foreach ($m as $gi => $group) {
            if ($gi === 0) {
                continue;
            }
            [$gtext, $gstart] = $group;
            $groups[$gi] = $gstart < 0 ? null : $gtext;
        }

        return new CMatch(
            $subject,
            $source,
            $base + Text::bytesToCp($segment, $relStart),
            $base + Text::bytesToCp($segment, $relStart + strlen($text)),
            $text,
            $groups,
        );
    }

    public static function searchPositions(string $source, string $subject, bool $ignoreCase = true, ?int $byteEnd = null): array
    {
        $segment = $byteEnd === null ? $subject : substr($subject, 0, $byteEnd);
        $m = [];
        $ok = @preg_match_all(self::pattern($source, $ignoreCase), $segment, $m, PREG_OFFSET_CAPTURE);
        if ($ok === false || $ok === 0) {
            return [];
        }
        $positions = [];
        foreach ($m[0] as [$text, $start]) {
            $positions[] = ['start' => $start, 'end' => $start + strlen($text)];
        }

        return $positions;
    }

    public static function searchOne(string $source, string $subject, bool $ignoreCase = true, int $byteOffset = 0): ?array
    {
        $m = [];
        $segment = $byteOffset > 0 ? substr($subject, $byteOffset) : $subject;
        $ok = @preg_match(self::pattern($source, $ignoreCase), $segment, $m, PREG_OFFSET_CAPTURE);
        if ($ok !== 1) {
            return null;
        }
        [$text, $start] = $m[0];

        return ['start' => $byteOffset + $start, 'end' => $byteOffset + $start + strlen($text), 'text' => $text];
    }

    public static function search(string $source, string $subject, bool $ignoreCase = true): bool
    {
        return @preg_match(self::pattern($source, $ignoreCase), $subject) === 1;
    }
}
