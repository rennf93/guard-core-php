<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Detection;

use RenzoFranceschini\GuardCore\Support\Text;

final class Matchers
{
    public const FILE_UPLOAD_DANGEROUS_EXTENSIONS = [
        'phar', 'phtml', 'pht', 'exe', 'jsp', 'jspx', 'aspx', 'asp', 'asa',
        'asax', 'ascx', 'ashx', 'asmx', 'cer', 'phps', 'shtml', 'cfm', 'cfc',
        'war', 'bash', 'sh', 'rb', 'py', 'pl', 'cgi', 'com', 'bat', 'cmd',
        'vbs', 'vbe', 'js', 'ws', 'wsf', 'msi', 'hta',
    ];

    public const FILE_UPLOAD_BENIGN_TERMINAL_EXTENSIONS = [
        'jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp', 'svg', 'ico', 'tif',
        'tiff', 'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'odt',
        'mp3', 'mp4', 'avi', 'mov', 'wav', 'webm', 'mkv',
    ];

    private static array $alternations = [];

    public static function dangerousExtAlternation(bool $includeCom): string
    {
        $key = $includeCom ? 'd' : 'n';
        if (!isset(self::$alternations[$key])) {
            $exts = self::FILE_UPLOAD_DANGEROUS_EXTENSIONS;
            if (!$includeCom) {
                $exts = array_values(array_diff($exts, ['com']));
            }
            usort($exts, static function (string $a, string $b): int {
                return strlen($b) <=> strlen($a) ?: strcmp($a, $b);
            });
            self::$alternations[$key] = 'php\\d*|' . implode('|', array_map('preg_quote', $exts));
        }

        return self::$alternations[$key];
    }

    public static function benignTerminalAlternation(): string
    {
        $key = 'b';
        if (!isset(self::$alternations[$key])) {
            $exts = self::FILE_UPLOAD_BENIGN_TERMINAL_EXTENSIONS;
            usort($exts, static function (string $a, string $b): int {
                return strlen($b) <=> strlen($a) ?: strcmp($a, $b);
            });
            self::$alternations[$key] = implode('|', array_map('preg_quote', $exts));
        }

        return self::$alternations[$key];
    }

    public static function boundedFindIter(string $text, string $source, string $prefix, string $terminator): array
    {
        $termEnds = [];
        foreach (Preg::allMatches($terminator, $text) as $m) {
            $termEnds[] = $m['end'];
        }
        if ($termEnds === []) {
            return [];
        }
        $ceiling = $termEnds[count($termEnds) - 1];
        $prefixStarts = [];
        foreach (Preg::allMatches($prefix, $text) as $m) {
            $prefixStarts[] = $m['start'];
        }
        if ($prefixStarts === []) {
            return [];
        }
        $matches = [];
        $searchFrom = 0;
        while (true) {
            $match = self::matchFromLivePrefixes($text, $source, $prefixStarts, $searchFrom, $ceiling);
            if ($match === null) {
                break;
            }
            $matches[] = $match;
            $searchFrom = $match['end'] > $match['start'] ? $match['end'] : $match['start'] + 1;
        }

        return $matches;
    }

    private static function matchFromLivePrefixes(string $text, string $source, array $prefixStarts, int $searchFrom, int $ceiling): ?array
    {
        foreach ($prefixStarts as $start) {
            if ($start < $searchFrom) {
                continue;
            }
            if ($start >= $ceiling) {
                break;
            }
            $match = Preg::matchAnchoredAt($source, $text, $start, $ceiling);
            if ($match !== null) {
                return $match;
            }
        }

        return null;
    }

    public static function cmdInjectionShellDashCFinditer(string $text, string $compiled): array
    {
        $matches = [];
        $lastEnd = 0;
        foreach (Preg::allMatches('\\n[^\\S\\r\\n]*', $text) as $prefix) {
            $start = $prefix['start'];
            if ($start < $lastEnd) {
                continue;
            }
            $pos = $prefix['end'];
            while (true) {
                $token = Preg::matchAnchoredAt('[^=\\s;|&]+=[^\\s;|&]+\\s+', $text, $pos);
                if ($token === null) {
                    break;
                }
                $pos = $token['end'];
            }
            $match = Preg::matchAnchoredAt($compiled, $text, $start);
            if ($match !== null) {
                $matches[] = $match;
                $lastEnd = $match['end'];
            } else {
                $lastEnd = $pos;
            }
        }

        return $matches;
    }

    public static function ldapNullByteAttrFinditer(string $text, string $compiled, string $tailSource): array
    {
        if (!str_contains($text, '*') || !str_contains($text, ')')) {
            return [];
        }
        $matches = [];
        $lastEnd = 0;
        foreach (Preg::allMatches($tailSource, $text) as $tail) {
            $starPos = $tail['start'];
            if ($starPos < $lastEnd) {
                continue;
            }
            $valueStart = self::ldapNullByteValueStart($text, $starPos);
            if ($valueStart === 0 || $text[$valueStart - 1] !== '=') {
                continue;
            }
            $nameStart = self::ldapNullByteAttrNameStart($text, $valueStart - 1);
            if ($nameStart === null) {
                continue;
            }
            $match = Preg::matchAnchoredAt($compiled, $text, $nameStart, $tail['end']);
            if ($match !== null) {
                $matches[] = $match;
                $lastEnd = $match['end'];
            }
        }

        return $matches;
    }

    private static function ldapNullByteValueStart(string $text, int $starPos): int
    {
        $i = $starPos;
        while ($i > 0 && preg_match('/(*UCP)[\\d\\w\\s]/u', Text::slice($text, self::cpIndexBefore($text, $i), 1)) === 1) {
            $i = self::cpIndexBefore($text, $i);
        }

        return $i;
    }

    private static function ldapNullByteAttrNameStart(string $text, int $equalsPos): ?int
    {
        $i = $equalsPos;
        while ($i > 0 && preg_match('/(*UCP)[\\w-]/u', Text::slice($text, self::cpIndexBefore($text, $i), 1)) === 1) {
            $i = self::cpIndexBefore($text, $i);
        }
        if ($i === $equalsPos || preg_match('/[a-zA-Z]/', $text[$i] ?? '') !== 1) {
            return null;
        }

        return $i;
    }

    private static function cpIndexBefore(string $text, int $byteOffset): int
    {
        $byteOffset--;
        while ($byteOffset > 0 && (ord($text[$byteOffset]) & 0xc0) === 0x80) {
            $byteOffset--;
        }

        return $byteOffset;
    }

    public static function quoteSpliceFinditer(string $text, string $compiled): array
    {
        $n = strlen($text);
        $matches = [];
        $lastEnd = 0;
        foreach (Preg::allMatches("['\\\"]+", $text) as $quote) {
            if ($quote['start'] < $lastEnd) {
                continue;
            }
            if ($quote['end'] >= $n || preg_match('/(*UCP)\\w/u', Text::slice($text, self::cpIndexAt($text, $quote['end']), 1)) !== 1) {
                continue;
            }
            $wordStart = self::quoteSpliceWordStart($text, $quote['start']);
            if ($wordStart === null) {
                continue;
            }
            $match = Preg::matchAnchoredAt($compiled, $text, $wordStart);
            if ($match !== null) {
                $matches[] = $match;
                $lastEnd = $match['end'];
            } else {
                $lastEnd = $quote['end'];
            }
        }

        return $matches;
    }

    private static function cpIndexAt(string $text, int $byteOffset): int
    {
        while ($byteOffset > 0 && (ord($text[$byteOffset]) & 0xc0) === 0x80) {
            $byteOffset--;
        }

        return $byteOffset;
    }

    private static function quoteSpliceWordStart(string $text, int $pos): ?int
    {
        $i = $pos;
        while ($i > 0 && preg_match('/(*UCP)\\w/u', Text::slice($text, self::cpIndexBefore($text, $i), 1)) === 1) {
            $i = self::cpIndexBefore($text, $i);
        }

        return $i < $pos ? $i : null;
    }

    public static function loadFileScanMatches(string $content, string $compiled): array
    {
        return self::boundedFindIter($content, $compiled, 'LOAD_FILE\\s*\\(', '\\)');
    }

    public static function cmdInjectionDollarScanMatches(string $content, string $compiled): array
    {
        return array_merge(
            self::boundedFindIter($content, $compiled, '[;&|]\\s*\\$\\(', '\\)'),
            self::boundedFindIter($content, $compiled, '[;&|]\\s*\\$\\{', '\\}'),
        );
    }

    public static function globWildcardScanMatches(string $content, string $compiled): array
    {
        $matches = [];
        foreach (Preg::allMatches('[\\w./*?-]+', $content) as $run) {
            $runStart = $run['start'];
            $runEnd = $run['end'];
            if (preg_match('/[?*]/', substr($content, $runStart, $runEnd - $runStart)) !== 1) {
                continue;
            }
            $match = Preg::matchAnchoredAt($compiled, $content, $runStart, $runEnd);
            if ($match !== null) {
                $matches[] = $match;
            }
        }

        return $matches;
    }

    private static function regionFind(string $content, string $needle, int $from, ?int $to = null): int|false
    {
        $limit = $to ?? strlen($content);
        $pos = $from;
        while ($pos <= $limit - strlen($needle)) {
            $idx = strpos($content, $needle, $pos);
            if ($idx === false || $idx + strlen($needle) > $limit) {
                return false;
            }

            return $idx;
        }

        return false;
    }

    private static function templateRegions(string $content, string $opening, string $closing): array
    {
        $regions = [];
        $cursor = 0;
        while (($start = self::regionFind($content, $opening, $cursor)) !== false) {
            $bodyStart = $start + strlen($opening);
            $barrier = self::regionFind($content, $closing[0], $bodyStart);
            if ($barrier === false) {
                return $regions;
            }
            $cursor = max($bodyStart, $barrier - strlen($opening) + 1);
            if (substr($content, $barrier, strlen($closing)) === $closing) {
                $regions[] = [$start, $barrier, $barrier + strlen($closing)];
            }
        }

        return $regions;
    }

    private static function templateFrame(string $content, string $opening, string $closing, int $start, int $end): array
    {
        $source = preg_quote($opening, "\x01") . '[^' . preg_quote($closing[0], "\x01") . ']*' . preg_quote($closing, "\x01");
        $match = Preg::matchAnchoredAt($source, $content, $start, $end);
        \assert($match !== null);

        return $match;
    }

    public static function templateKeywordMatches(string $content, string $compiled, string $opening, string $closing): array
    {
        $indicator = '(?:system|exec|popen|eval|require|include)\\s*\\z';
        $matches = [];
        foreach (self::templateRegions($content, $opening, $closing) as [$start, $barrier, $end]) {
            $segFrom = $start + strlen($opening) + 1;
            $seg = substr($content, $segFrom, $barrier - $segFrom);
            if (preg_match(Preg::compile($indicator), $seg) === 1) {
                $matches[] = self::templateFrame($content, $opening, $closing, $start, $end);
            }
        }

        return $matches;
    }

    private static function templateAfterDates(string $content, string $opening, int $start, int $barrier): int
    {
        $lastDate = -1;
        foreach (Preg::allMatches('(?=\\d{4}-\\d{1,2}-\\d{1,2}(?!\\d))', $content) as $m) {
            if ($m['start'] >= $start + 2 && $m['start'] < $barrier) {
                $lastDate = $m['start'];
            }
        }
        if ($lastDate !== -1) {
            $found = self::regionFind($content, $opening, $lastDate + 1, $barrier);

            return $found === false ? -1 : $found;
        }

        return $start;
    }

    public static function templateExpressionMatches(string $content, string $compiled, string $kind): array
    {
        $spec = [
            'dollar' => ['${', '}', '@[\\w.]+@|\\b\\w+\\s*\\(|(?<!\\d)\\d+\\s*[*/%+\\-]\\s*\\d+'],
            'curly' => ['{{', '}}', '@[\\w.]+@|\\b\\w+\\(\\s*\\)|(?<!\\d)[\'\\"]?\\d+[\'\\"]?\\s*[*/%+\\-]\\s*[\'\\"]?\\d+[\'\\"]?'],
            'hash' => ['#{', '}', '@[\\w.]+@|\\b\\w+\\s*\\(|(?<!\\d)[\'\\"]?\\d+[\'\\"]?\\s*[*/%+\\-]\\s*[\'\\"]?\\d+[\'\\"]?'],
            'asp' => ['<%', '%>', 'system|exec|eval|`|Runtime|IO\\.|File\\.|Dir\\.|(?<!\\d)\\d+\\s*[-+*/]\\s*\\d+'],
        ][$kind];
        [$opening, $closing, $indicatorSource] = $spec;
        $matches = [];
        $lastEnd = 0;
        foreach (self::templateRegions($content, $opening, $closing) as [$start, $barrier, $end]) {
            if ($start < $lastEnd) {
                continue;
            }
            if ($kind === 'curly' || $kind === 'hash') {
                $start = self::templateAfterDates($content, $opening, $start, $barrier);
            }
            if ($start === -1) {
                continue;
            }
            $segFrom = $start + strlen($opening);
            $seg = substr($content, $segFrom, $barrier - $segFrom);
            if (preg_match(Preg::compile($indicatorSource), $seg) === 1) {
                $matches[] = self::templateFrame($content, $opening, $closing, $start, $end);
                $lastEnd = $end;
            }
        }

        return $matches;
    }

    private const PICKLE_GLOBAL_IDENT_MAX_LEN = 101;
    private const PICKLE_GLOBAL_DOTTED_SEGMENTS_MAX = 20;

    public static function pickleGlobalGenericFinditer(string $text, string $compiled): array
    {
        $newlinePositions = [];
        foreach (Preg::allMatches('\n', $text) as $m) {
            $newlinePositions[] = $m['start'];
        }
        if (count($newlinePositions) < 2) {
            return [];
        }
        $nonModulePositions = [];
        foreach (Preg::allMatches('[^A-Za-z0-9_.]', $text, false) as $m) {
            $nonModulePositions[] = $m['start'];
        }
        $matches = [];
        $lastEnd = 0;
        $count = count($newlinePositions);
        for ($i = 0; $i + 1 < $count; $i++) {
            $nl1 = $newlinePositions[$i];
            $nl2 = $newlinePositions[$i + 1];
            if ($nl1 < $lastEnd) {
                continue;
            }
            $ident = substr($text, $nl1 + 1, $nl2 - $nl1 - 1);
            if (preg_match('/\\A[A-Za-z_][A-Za-z0-9_]{0,100}\\z/i', $ident) !== 1) {
                continue;
            }
            $runStart = self::pickleGlobalRunStart($nonModulePositions, $nl1, $lastEnd);
            $start = self::pickleGlobalChainStart($text, $nl1, $runStart);
            if ($start === null) {
                continue;
            }
            $match = Preg::matchAnchoredAt($compiled, $text, $start);
            if ($match !== null) {
                $matches[] = $match;
                $lastEnd = $match['end'];
            }
        }

        return $matches;
    }

    private static function pickleGlobalRunStart(array $nonModulePositions, int $nl1, int $floor): int
    {
        $idx = 0;
        $hi = count($nonModulePositions);
        while ($idx < $hi && $nonModulePositions[$idx] < $nl1) {
            $idx++;
        }

        return $idx > 0 ? max($floor, $nonModulePositions[$idx - 1] + 1) : $floor;
    }

    private static function pickleGlobalFirstValidMarker(string $text, int $floor, int $ceiling): ?int
    {
        $start = $floor;
        while (true) {
            $posLower = self::findIn($text, 'c', $start, $ceiling);
            $posUpper = self::findIn($text, 'C', $start, $ceiling);
            $candidates = [];
            if ($posLower !== null) {
                $candidates[] = $posLower;
            }
            if ($posUpper !== null) {
                $candidates[] = $posUpper;
            }
            if ($candidates === []) {
                return null;
            }
            $pos = min($candidates);
            if ($pos + 1 < strlen($text) && preg_match('/[A-Za-z_]/i', $text[$pos + 1]) === 1) {
                return $pos;
            }
            $start = $pos + 1;
        }
    }

    private static function findIn(string $text, string $needle, int $from, int $to): ?int
    {
        if ($from >= $to) {
            return null;
        }
        $idx = strpos($text, $needle, $from);
        if ($idx === false || $idx >= $to) {
            return null;
        }

        return $idx;
    }

    private static function pickleGlobalChainStart(string $text, int $nl1, int $floor): ?int
    {
        $segEnd = $nl1;
        $earliest = null;
        for ($i = 0; $i <= self::PICKLE_GLOBAL_DOTTED_SEGMENTS_MAX; $i++) {
            $dotPos = false;
            $searchFrom = $floor;
            while ($searchFrom <= $segEnd) {
                $idx = strpos($text, '.', $searchFrom);
                if ($idx === false || $idx >= $segEnd) {
                    break;
                }
                $dotPos = $idx;
                $searchFrom = $idx + 1;
            }
            $segStart = $dotPos !== false && $dotPos >= $floor ? $dotPos + 1 : $floor;
            $segFloor = max($segStart, $segEnd - self::PICKLE_GLOBAL_IDENT_MAX_LEN - 1);
            $cPos = self::pickleGlobalFirstValidMarker($text, $segFloor, $segEnd);
            if ($cPos !== null) {
                $earliest = $cPos;
            }
            $segmentOk = false;
            if ($dotPos !== false && $dotPos >= $floor) {
                $segment = substr($text, $segStart, $segEnd - $segStart);
                $segmentOk = preg_match('/\\A[A-Za-z_][A-Za-z0-9_]{0,100}\\z/i', $segment) === 1;
            }
            if ($dotPos === false || $dotPos < $floor || !$segmentOk) {
                break;
            }
            $segEnd = $dotPos;
        }

        return $earliest;
    }

    public static function fileUploadScanMatches(string $content, string $kind): array
    {
        $matches = [];
        $lastEnd = 0;
        foreach (Preg::allMatches('filename', $content) as $token) {
            $candidate = self::fileUploadQuotedCandidate($content, $token['start']);
            if ($candidate === null) {
                continue;
            }
            [$start, $bodyStart, $end] = $candidate;
            if ($start < $lastEnd || !self::fileUploadKindMatches(substr($content, $bodyStart, $end - 1 - $bodyStart), $kind)) {
                continue;
            }
            $matches[] = [
                'start' => $start,
                'end' => $end,
                'text' => substr($content, $start, $end - $start),
                'groups' => [],
            ];
            $lastEnd = $end;
        }

        return $matches;
    }

    private static function fileUploadMatchStart(string $content, int $filenameStart): ?int
    {
        $cursor = $filenameStart - 1;
        $firstNewline = -1;
        while ($cursor >= 0 && self::isSpaceByte($content[$cursor])) {
            if ($content[$cursor] === "\n") {
                $firstNewline = $cursor;
            }
            $cursor--;
        }
        if ($cursor === -1) {
            return 0;
        }
        if (str_contains(';,:\n', $content[$cursor])) {
            return $cursor;
        }

        return $firstNewline !== -1 ? $firstNewline : null;
    }

    private static function isSpaceByte(string $byte): bool
    {
        return str_contains(" \t\n\r\013\014", $byte);
    }

    private static function fileUploadQuotedCandidate(string $content, int $filenameStart): ?array
    {
        $matchStart = self::fileUploadMatchStart($content, $filenameStart);
        if ($matchStart === null) {
            return null;
        }
        $cursor = self::skipSpace($content, $filenameStart + strlen('filename'));
        if ($cursor === strlen($content) || $content[$cursor] !== '=') {
            return null;
        }
        $cursor = self::skipSpace($content, $cursor + 1);
        if ($cursor === strlen($content) || ($content[$cursor] !== '"' && $content[$cursor] !== "'")) {
            return null;
        }
        $bodyStart = $cursor + 1;
        $quote = Preg::searchFrom("['\\\"]", $content, $bodyStart);
        if ($quote === null) {
            return null;
        }

        return [$matchStart, $bodyStart, $quote['end']];
    }

    private static function skipSpace(string $content, int $cursor): int
    {
        $n = strlen($content);
        while ($cursor < $n && self::isSpaceByte($content[$cursor])) {
            $cursor++;
        }

        return $cursor;
    }

    private static function dangerousExtensionMarkers(string $body, ?int $finalDot): array
    {
        $alt = self::dangerousExtAlternation(true);
        $subject = $body;
        if ($finalDot !== null) {
            $subject = substr($body, 0, $finalDot);
        }
        $out = [];
        foreach (Preg::allMatches('\\.(?:' . $alt . ')', $subject) as $m) {
            if ($finalDot !== null && $m['end'] >= $finalDot) {
                $m['lookaheadOk'] = true;
            } else {
                $next = $m['end'] < strlen($body) ? $body[$m['end']] : '';
                $m['lookaheadOk'] = $next === '' || !preg_match('/[A-Za-z0-9]/', $next);
            }
            $out[] = $m;
        }

        return $out;
    }

    private static function fileUploadIsDoubleExtension(string $body): bool
    {
        if (preg_match('/\\.(?:' . self::benignTerminalAlternation() . ')\\z/i', $body) !== 1) {
            return false;
        }
        $finalDot = strrpos($body, '.');
        if ($finalDot === false) {
            return false;
        }
        foreach (self::dangerousExtensionMarkers($body, $finalDot) as $dangerous) {
            if (!$dangerous['lookaheadOk']) {
                continue;
            }
            $suffixStart = $dangerous['end'];
            if ($suffixStart === $finalDot) {
                return true;
            }
            if ($suffixStart < $finalDot && !str_contains(" \"'", $body[$suffixStart])) {
                return true;
            }
        }

        return false;
    }

    private static function truncationMarkerMatchesAt(string $body, int $pos, bool $decoded): bool
    {
        if ($decoded) {
            $alternatives = ["\x00", ';'];
        } else {
            $alternatives = ['%00', '\\u0000', '\\x00', '\\0', "\x00", ';'];
        }
        $rest = substr($body, $pos);
        foreach ($alternatives as $alt) {
            if (str_starts_with($rest, $alt)) {
                return true;
            }
        }

        return $rest === '.';
    }

    private static function fileUploadIsTruncation(string $body, bool $decoded): bool
    {
        foreach (self::dangerousExtensionMarkers($body, null) as $dangerous) {
            if (!$dangerous['lookaheadOk']) {
                continue;
            }
            if (self::truncationMarkerMatchesAt($body, $dangerous['end'], $decoded)) {
                return true;
            }
        }

        return false;
    }

    public static function fileUploadKindMatches(string $body, string $kind): bool
    {
        switch ($kind) {
            case 'file_upload_dangerous':
                return preg_match('/\\.(?:' . self::dangerousExtAlternation(true) . ')\\z/i', $body) === 1;
            case 'file_upload_double':
                return self::fileUploadIsDoubleExtension($body);
            case 'file_upload_truncation':
                return self::fileUploadIsTruncation($body, false);
            case 'file_upload_decoded_truncation':
                return self::fileUploadIsTruncation($body, true);
        }

        return false;
    }
}
