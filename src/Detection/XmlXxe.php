<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Detection;

final class XmlXxe
{
    public static function firstAtOrAfter(array $sortedPositions, int $floor): ?int
    {
        $lo = 0;
        $hi = count($sortedPositions);
        while ($lo < $hi) {
            $mid = intdiv($lo + $hi, 2);
            if ($sortedPositions[$mid] < $floor) {
                $lo = $mid + 1;
            } else {
                $hi = $mid;
            }
        }

        return $lo < count($sortedPositions) ? $sortedPositions[$lo] : null;
    }

    private static function positions(string $source, string $text): array
    {
        $out = [];
        foreach (Preg::allMatches($source, $text) as $m) {
            $out[] = $m['start'];
        }

        return $out;
    }

    public static function xmlSystemFinditer(string $text): array
    {
        $ends = self::positions('>', $text);
        $matches = [];
        $lastEnd = 0;
        foreach (Preg::allMatches('<!(?:ENTITY|DOCTYPE)', $text) as $prefix) {
            if ($prefix['start'] < $lastEnd) {
                continue;
            }
            $end = self::firstAtOrAfter($ends, $prefix['end']);
            if ($end === null) {
                break;
            }
            $lastEnd = $end + 1;
            $needle = substr($text, $prefix['end'] + 1, max(0, $end - 1 - ($prefix['end'] + 1)));
            if (Preg::hasMatch('SYSTEM', $needle)) {
                $matches[] = [
                    'start' => $prefix['start'],
                    'end' => $lastEnd,
                    'text' => substr($text, $prefix['start'], $lastEnd - $prefix['start']),
                    'groups' => [],
                ];
            }
        }

        return $matches;
    }

    public static function xmlInternalEntityFinditer(string $text): array
    {
        $boundaries = self::positions('[>\\[]', $text);
        $entities = self::positions('<!ENTITY', $text);
        $matches = [];
        $lastEnd = 0;
        foreach (Preg::allMatches('<!DOCTYPE', $text) as $prefix) {
            if ($prefix['start'] < $lastEnd) {
                continue;
            }
            $boundary = self::firstAtOrAfter($boundaries, $prefix['end']);
            if ($boundary === null) {
                break;
            }
            $lastEnd = $boundary + 1;
            if ($text[$boundary] !== '[') {
                continue;
            }
            $entity = self::firstAtOrAfter($entities, $boundary + 1);
            if ($entity === null) {
                break;
            }
            $lastEnd = $entity + 8;
            $matches[] = [
                'start' => $prefix['start'],
                'end' => $lastEnd,
                'text' => substr($text, $prefix['start'], $lastEnd - $prefix['start']),
                'groups' => [],
            ];
        }

        return $matches;
    }

    private static function schemeCompletionEnd(string $text, int $schemeStart, array $class12, array $class3): ?int
    {
        if ($schemeStart === 0 || !str_contains("\"'", $text[$schemeStart - 1])) {
            return null;
        }
        $scheme = Preg::matchAnchoredAt('https?://', $text, $schemeStart);
        if ($scheme === null) {
            return null;
        }
        $schemeEnd = $scheme['end'];
        if (Preg::matchAnchoredAt('(?:www\.)?w3\.org/', $text, $schemeEnd) !== null) {
            return null;
        }

        return self::quotedUrlEnd($text, $schemeEnd, $class12, $class3);
    }

    private static function quotedUrlEnd(string $text, int $schemeEnd, array $class12, array $class3): ?int
    {
        $quote2 = self::firstAtOrAfter($class3, $schemeEnd);
        if ($quote2 === null || $quote2 === $schemeEnd || $text[$quote2] === '>') {
            return null;
        }
        $finalBoundary = self::firstAtOrAfter($class12, $quote2 + 1);
        if ($finalBoundary === null) {
            return null;
        }

        return $text[$finalBoundary] === '>' ? $finalBoundary : null;
    }

    private static function publicRunBounds(array $class12, int $publicPos, int $textLen): array
    {
        $runIdx = 0;
        $n = count($class12);
        while ($runIdx < $n && $class12[$runIdx] <= $publicPos) {
            $runIdx++;
        }
        $runStart = $runIdx > 0 ? $class12[$runIdx - 1] + 1 : 0;
        $runEnd = $runIdx < $n ? $class12[$runIdx] : $textLen;

        return [$runStart, $runEnd];
    }

    public static function xmlXxePublicExternalDtdFinditer(string $text): array
    {
        $doctypePositions = self::positions('<!DOCTYPE', $text);
        $publicPositions = self::positions('PUBLIC', $text);
        if ($doctypePositions === [] || $publicPositions === []) {
            return [];
        }
        $class12 = self::positions('[>\\[]', $text);
        $class3 = self::positions('[\"\'>]', $text);
        $quotePositions = [];
        $quoteToFinalGt = [];
        foreach (Preg::allMatches('https?://', $text) as $scheme) {
            $finalGt = self::schemeCompletionEnd($text, $scheme['start'], $class12, $class3);
            if ($finalGt === null) {
                continue;
            }
            $quotePos = $scheme['start'] - 1;
            $quotePositions[] = $quotePos;
            $quoteToFinalGt[$quotePos] = $finalGt;
        }
        if ($quotePositions === []) {
            return [];
        }
        sort($quotePositions);
        $textLen = strlen($text);
        $matches = [];
        $lastEnd = 0;
        foreach ($publicPositions as $publicPos) {
            if ($publicPos < $lastEnd) {
                continue;
            }
            [$runStart, $runEnd] = self::publicRunBounds($class12, $publicPos, $textLen);
            $doctypeBefore = self::firstAtOrAfter($doctypePositions, $runStart);
            if ($doctypeBefore === null || $doctypeBefore >= $publicPos - 9) {
                continue;
            }
            $quote1 = self::firstAtOrAfter($quotePositions, $publicPos + 7);
            if ($quote1 === null || $quote1 >= $runEnd) {
                continue;
            }
            $finalGt = $quoteToFinalGt[$quote1];
            $end = $finalGt + 1;
            $matches[] = [
                'start' => $doctypeBefore,
                'end' => $end,
                'text' => substr($text, $doctypeBefore, $end - $doctypeBefore),
                'groups' => [],
            ];
            $lastEnd = $end;
        }

        return $matches;
    }
}
