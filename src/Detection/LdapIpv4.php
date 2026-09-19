<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Detection;

final class LdapIpv4
{
    public const LDAP_BREAKOUT_LOCAL_SCAN_CHARS = 40;

    public static function decodeLegacyIpv4Part(string $part): ?int
    {
        if (str_starts_with($part, '0x') || str_starts_with($part, '0X')) {
            $digits = substr($part, 2);
            if ($digits === '') {
                return null;
            }
            if (!preg_match('/\A[0-9a-fA-F]+\z/', $digits)) {
                return null;
            }

            return (int) hexdec($digits);
        }
        if (str_starts_with($part, '0') && strlen($part) > 1) {
            $digits = substr($part, 1);
            if (!preg_match('/\A[0-7]+\z/', $digits)) {
                return null;
            }

            return (int) octdec($digits);
        }
        if (!preg_match('/\A[0-9]+\z/', $part)) {
            return null;
        }

        return (int) $part;
    }

    public static function decodeLegacyIpv4Host(string $host): ?int
    {
        $parts = explode('.', $host);
        $count = count($parts);
        if ($count < 1 || $count > 4) {
            return null;
        }
        $decoded = [];
        foreach ($parts as $part) {
            $value = self::decodeLegacyIpv4Part($part);
            if ($value === null) {
                return null;
            }
            $decoded[] = $value;
        }
        if (count($decoded) === 1 && $decoded[0] !== 0) {
            $isSmall = $decoded[0] < (1 << 24);
            $isBare = $parts[0] === '0' || $parts[0][0] !== '0';
            if ($isSmall && $isBare) {
                return null;
            }
        }
        for ($i = 0; $i < $count - 1; $i++) {
            if ($decoded[$i] > 255) {
                return null;
            }
        }
        $remainingBits = 8 * (5 - $count);
        if ($decoded[$count - 1] >= (1 << $remainingBits)) {
            return null;
        }
        $result = 0;
        for ($i = 0; $i < $count - 1; $i++) {
            $result = ($result << 8) | $decoded[$i];
        }

        return ($result << $remainingBits) | $decoded[$count - 1];
    }

    private static function isBlockedLegacyIpv4(int $ipInt): bool
    {
        foreach (self::blockedNetworks() as [$net, $mask]) {
            if (($ipInt & $mask) === $net) {
                return true;
            }
        }

        return false;
    }

    private static function blockedNetworks(): array
    {
        return [
            [0x00000000, 0xff000000],
            [0x7f000000, 0xff000000],
            [0x0a000000, 0xff000000],
            [0xac100000, 0xfff00000],
            [0xc0a80000, 0xffff0000],
            [0xa9fe0000, 0xffff0000],
            [0x646464c8, 0xffffffff],
        ];
    }

    public static function legacyIpv4MatchIsBlocked(array $match): bool
    {
        $ipInt = self::decodeLegacyIpv4Host($match['groups'][1]['text'] ?? '');

        return $ipInt !== null && self::isBlockedLegacyIpv4($ipInt);
    }

    private static function nextCandidateScanLimit(array $match, string $source, string $text, int $after): int
    {
        $next = Preg::searchFrom($source, $text, $after);

        return $next !== null ? $next['end'] : strlen($text);
    }

    public static function wildcardChainIsInjection(string $text, array $match, string $source): bool
    {
        $groupText = $match['text'];
        $rel = strpos($groupText, ')');
        if ($rel === false) {
            return false;
        }
        $closeParenPos = $match['start'] + $rel;

        $backwardStart = max(0, $closeParenPos - self::LDAP_BREAKOUT_LOCAL_SCAN_CHARS);
        $position = $closeParenPos - 1;
        $depth = 0;
        while ($position >= $backwardStart) {
            $ch = $text[$position];
            if (str_contains("\"'\n&", $ch)) {
                break;
            }
            if ($ch === ')') {
                $depth--;
            } elseif ($ch === '(') {
                $depth++;
            }
            $position--;
        }
        $backwardWindow = substr($text, $position + 1, $closeParenPos - ($position + 1));
        $depthUnresolved = $backwardStart > 0 && $position < $backwardStart;

        $scanLimit = self::nextCandidateScanLimit($match, $source, $text, $match['end']);
        $extent = self::filterExpressionForwardExtent($text, $closeParenPos + 1, $scanLimit);
        $forwardWindow = substr($text, $closeParenPos, $extent - $closeParenPos);

        $wildcardAdjacent = str_starts_with($groupText, '*');
        $depthProvesBreakout = $depth <= 0 && ($wildcardAdjacent || !$depthUnresolved);
        $wildcardClause = preg_match('/=[^()]+\*\s*\z/', $backwardWindow) === 1;
        if (!$depthProvesBreakout && !$wildcardClause) {
            return false;
        }

        return preg_match('/\*|\(\s*[&|!]|\x00|\(\s*\(|~=|>=|<=/', $backwardWindow) === 1
            || preg_match('/\*|\(\s*[&|!]|\x00|\(\s*\(|~=|>=|<=/', $forwardWindow) === 1;
    }

    public static function parenConjunctionIsInjection(string $text, array $match, string $source): bool
    {
        $scanLimit = self::nextCandidateScanLimit($match, $source, $text, $match['end']);
        $tailEnd = self::filterExpressionForwardExtent($text, $match['end'], $scanLimit);
        $tail = substr($text, $match['end'], $tailEnd - $match['end']);
        if (preg_match('/\A\s*(?:[!(]|\*)/', $tail) === 1) {
            return true;
        }
        if (!str_contains($tail, '=')) {
            return false;
        }

        return preg_match('/\A\s*(?::)?(?:[a-zA-Z][\w.-]*|\d+(?:\.\d+)*)(?:;[\w.-]+)*(?::[\w.-]+)*\s*:?=/', $tail) === 1;
    }

    public static function filterExpressionForwardExtent(string $text, int $start, int $scanLimit): int
    {
        $position = $start;
        $depth = 0;
        while (true) {
            if ($position >= $scanLimit) {
                return $scanLimit;
            }
            $boundary = Preg::matchAnchoredAt('[()\"\'\n]', $text, $position, $scanLimit);
            if ($boundary === null) {
                return $scanLimit;
            }
            $char = $boundary['text'];
            if (str_contains("\"'\n", $char)) {
                return $boundary['start'];
            }
            if ($char === '(') {
                $depth++;
            } elseif ($depth === 0) {
                return $boundary['start'];
            } else {
                $depth--;
            }
            $position = $boundary['end'];
        }
    }
}
