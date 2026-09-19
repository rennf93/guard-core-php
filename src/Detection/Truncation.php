<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Detection;

use RenzoFranceschini\GuardCore\Support\Text;

final class Truncation
{
    public static function extractAttackRegions(string $content): array
    {
        $maxRegions = min(100, intdiv(10000, 100));
        $regions = [];
        foreach (Preprocessor::ATTACK_INDICATORS as $indicator) {
            $found = 0;
            foreach (Preg::allMatches($indicator, $content) as $m) {
                if ($found >= $maxRegions) {
                    break;
                }
                $start = max(0, $m['start'] - 100);
                $end = min(strlen($content), $m['end'] + 100);
                $regions[] = [$start, $end];
                $found++;
            }
            if (count($regions) >= $maxRegions) {
                break;
            }
        }
        if ($regions === []) {
            return [];
        }
        usort($regions, static fn (array $a, array $b): int => $a[0] <=> $b[0] ?: $a[1] <=> $b[1]);
        $merged = [$regions[0]];
        $count = count($regions);
        for ($i = 1; $i < $count; $i++) {
            [$start, $end] = $regions[$i];
            $last = count($merged) - 1;
            if ($start <= $merged[$last][1]) {
                $merged[$last][1] = max($merged[$last][1], $end);
            } else {
                $merged[] = [$start, $end];
            }
        }

        return array_slice($merged, 0, $maxRegions);
    }

    public static function capWithTail(string $content): string
    {
        $cap = Preprocessor::MAX_FULL_SCAN_BYTES;
        $tail = min(Preprocessor::FULL_SCAN_TAIL_BYTES, $cap);
        $headLen = $cap - $tail;

        return substr($content, 0, $headLen) . substr($content, -$tail);
    }

    public static function truncateSafely(string $content, Preprocessor $preprocessor): string
    {
        $maxFullScanBytes = Preprocessor::MAX_FULL_SCAN_BYTES;
        if (strlen($content) <= $maxFullScanBytes) {
            return $content;
        }
        $attackRegions = self::extractAttackRegions($content);
        if ($attackRegions === []) {
            return self::capWithTail($content);
        }
        $attackLength = 0;
        foreach ($attackRegions as [$s, $e]) {
            $attackLength += $e - $s;
        }
        if ($attackLength >= $maxFullScanBytes) {
            return self::extractAndConcatenateAttackRegions($content, $attackRegions, $maxFullScanBytes);
        }

        return self::buildResultWithAttackRegionsAndContext($content, $attackRegions, $maxFullScanBytes);
    }

    public static function extractAndConcatenateAttackRegions(string $content, array $attackRegions, int $budget): string
    {
        $result = '';
        $remaining = $budget;
        foreach ($attackRegions as [$start, $end]) {
            $chunkLen = min($end - $start, $remaining);
            $result .= substr($content, $start, $chunkLen);
            $remaining -= $chunkLen;
            if ($remaining <= 0) {
                break;
            }
        }

        return $result;
    }

    private static function consumeGap(string $content, int $lastEnd, int $start, int $gapBudget): array
    {
        $gapLen = $start - $lastEnd;
        if ($gapLen <= $gapBudget) {
            return [substr($content, $lastEnd, $start - $lastEnd), $gapBudget - $gapLen];
        }
        $chunkLen = $gapBudget - 1;
        $piece = $chunkLen > 0 ? substr($content, $lastEnd, $chunkLen) : '';

        return [$piece . ' ', 0];
    }

    public static function buildResultWithAttackRegionsAndContext(string $content, array $attackRegions, int $budget): string
    {
        $attackLength = 0;
        foreach ($attackRegions as [$s, $e]) {
            $attackLength += $e - $s;
        }
        $gapBudget = $budget - $attackLength;
        $parts = [];
        $lastEnd = 0;
        foreach ($attackRegions as [$start, $end]) {
            if ($lastEnd < $start && $gapBudget > 0) {
                [$piece, $gapBudget] = self::consumeGap($content, $lastEnd, $start, $gapBudget);
                $parts[] = $piece;
            }
            $parts[] = substr($content, $start, $end - $start);
            $lastEnd = $end;
        }
        $contentLen = strlen($content);
        if ($lastEnd < $contentLen && $gapBudget > 0) {
            $tailLen = min($contentLen - $lastEnd, $gapBudget);
            $parts[] = substr($content, $lastEnd, $tailLen);
        }

        return implode('', $parts);
    }
}
