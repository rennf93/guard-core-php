<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Detection;

use RenzoFranceschini\GuardCore\Support\Text;

final class ShellValidators
{
    public static function backtickWindowStart(string $content, int $position): int
    {
        $index = $position;
        while ($index > 0 && !str_contains("`'\"\n\r", $content[$index - 1])) {
            $index--;
        }

        return $index;
    }

    public static function backtickWindowEnd(string $content, int $position): int
    {
        $m = Preg::searchFrom("[`'\"\n\r]", $content, $position);

        return $m !== null ? $m['start'] : strlen($content);
    }

    public static function strongSqlKeywordGluedToPair(string $content, int $start, int $end): bool
    {
        $windowStart = self::backtickWindowStart($content, $start);
        $windowEnd = self::backtickWindowEnd($content, $end);
        $prefix = substr($content, $windowStart, $start - $windowStart);
        $suffix = substr($content, $end, $windowEnd - $end);
        if (preg_match('/(?:SELECT|FROM|WHERE|INSERT|UPDATE|DELETE|JOIN|VALUES|ORDER\s+BY|GROUP\s+BY)\z/i', $prefix) === 1) {
            return true;
        }

        return preg_match('/\A(?:SELECT|FROM|WHERE|INSERT|UPDATE|DELETE|JOIN|VALUES|ORDER\s+BY|GROUP\s+BY)\b/i', $suffix) === 1;
    }

    public static function gluedBacktickPairIsInjection(string $content, array $match, string $context): bool
    {
        $start = $match['start'];
        $end = $match['end'];
        $token = substr($content, $start + 1, $end - $start - 2);
        if (preg_match('/\A[\t\x20-\x7e]*\z/', $token) !== 1) {
            return false;
        }
        if (preg_match_all('/;|\|\||\||&&/', $token) >= 2) {
            return true;
        }
        $prefixGlued = $start > 0 && preg_match('/[A-Za-z0-9_]/', $content[$start - 1]) === 1;
        $suffixGlued = $end < strlen($content) && preg_match('/[A-Za-z0-9_]/', $content[$end]) === 1;
        $glued = $prefixGlued || $suffixGlued;

        $tailAnchored = trim(substr($content, $end)) === '';
        $clauseInitial = false;
        if ($start > 0 && str_contains(" \t\r\n", $content[$start - 1])) {
            $prefix = rtrim(substr($content, 0, $start));
            if ($prefix !== '') {
                $clauseInitial = str_contains('.!?;&|', $prefix[strlen($prefix) - 1]);
            }
        }
        $appendedClause = $tailAnchored && $clauseInitial;
        if (!$glued && !$appendedClause) {
            return false;
        }
        if (preg_match('/[\s\/.;|&$()]/', $token) === 1) {
            return true;
        }
        $windowStart = self::backtickWindowStart($content, $start);
        $windowEnd = self::backtickWindowEnd($content, $end);
        $window = substr($content, $windowStart, $windowEnd - $windowStart);
        if (preg_match('/(?:;|\|\||\||&&)\s*(?:`|[A-Za-z_][\w-]*|[~.\/][\w.\/-]*|-[\w-]*)|\$\(|\$\{/', $window) === 1) {
            return true;
        }
        if (self::strongSqlKeywordGluedToPair($content, $start, $end)) {
            return false;
        }
        $normalized = explode(':', $context, 2)[0];

        return in_array($normalized, ['query_param', 'url_path'], true) || $appendedClause;
    }

    public static function dollarSubstitutionPairIsInjection(string $content, array $match, string $context): bool
    {
        $start = $match['start'];
        $end = $match['end'];
        $prefixQuoted = $start > 0 && $content[$start - 1] === '`';
        $suffixQuoted = $end < strlen($content) && $content[$end] === '`';
        if ($prefixQuoted || $suffixQuoted) {
            return false;
        }
        $delimiter = $content[$start + 1];
        $token = substr($content, $start + 2, $end - $start - 3);
        if (self::dollarSubstitutionTokenIsImplausible($token, $delimiter)) {
            return true;
        }
        if (self::strongSqlKeywordGluedToPair($content, $start, $end)) {
            return false;
        }

        return in_array(explode(':', $context, 2)[0], ['query_param', 'url_path'], true);
    }

    private static function dollarSubstitutionTokenIsImplausible(string $token, string $delimiter): bool
    {
        $stripped = strtolower(trim($token));
        if ($stripped === 'ifs') {
            return true;
        }
        if ($delimiter === '{') {
            return preg_match('/\A[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*\z/', trim($token)) !== 1;
        }

        return preg_match('/[\/.;|&$()]/', $token) === 1;
    }

    public static function quoteSpliceTokenIsDangerousCommand(string $content, array $match): bool
    {
        $run = 0;
        foreach (preg_split('/[\'"]+/', $match['text']) as $fragment) {
            $run = Text::len($fragment) === 1 ? $run + 1 : 0;
            if ($run >= 3) {
                return true;
            }
        }

        return false;
    }

    public static function braceExpansionIsDangerousCommand(string $content, array $match): bool
    {
        $text = $match['text'];
        $start = strpos($text, '{');
        $end = strrpos($text, '}');
        if ($start === false || $end === false || $end <= $start) {
            return false;
        }
        $body = substr($text, $start + 1, $end - $start - 1);
        foreach (explode(',', $body) as $item) {
            if (preg_match('/\A[A-Za-z0-9_.\/~-]+\z/', $item) === 1 && preg_match('/[A-Za-z]/', $item) === 1) {
                return true;
            }
        }

        return false;
    }

    public static function globWildcardTokenIsDangerousCommand(string $content, array $match, string $context): bool
    {
        $token = $match['text'];
        if (!self::globWildcardTokenIsWordShaped($token)) {
            return false;
        }
        $suffix = $match['end'] < strlen($content) ? $content[$match['end']] : '';
        if ($suffix !== '' && !str_contains(" \t\r\n;|&", $suffix)) {
            return false;
        }
        $prefix = substr($content, 0, $match['start']);
        if (preg_match('/(?:;|\|\||\||&&|\$\(|`)\s*\z/', $prefix) === 1) {
            return true;
        }
        if ($context === 'request_body') {
            return trim($prefix) === '';
        }

        return false;
    }

    private static function globWildcardTokenIsWordShaped(string $token): bool
    {
        $len = Text::len($token);
        for ($i = 0; $i < $len; $i++) {
            $ch = Text::slice($token, $i, 1);
            if ($ch !== '?' && $ch !== '*') {
                continue;
            }
            $left = 0;
            $pos = $i - 1;
            while ($pos >= 0 && preg_match('/[A-Za-z]/', Text::slice($token, $pos, 1)) === 1) {
                $left++;
                $pos--;
            }
            $right = 0;
            $pos = $i + 1;
            while ($pos < $len && preg_match('/[A-Za-z]/', Text::slice($token, $pos, 1)) === 1) {
                $right++;
                $pos++;
            }
            if ($left + $right >= 2) {
                return true;
            }
        }

        return false;
    }
}
