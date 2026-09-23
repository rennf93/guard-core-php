<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Detection;

use RenzoFranceschini\GuardCore\Support\Text;

final class Semantic
{
    private const BINARY_CONTENT_RATIO_THRESHOLD = 0.2;
    private const MAX_TOKENS = 1000;
    private const MAX_TOKEN_CONTENT_LENGTH = 50000;
    private const MAX_ENTROPY_LENGTH = 10000;
    private const MAX_SCAN_LENGTH = 10000;
    private const MAX_AST_LENGTH = 1000;

    private const ATTACK_KEYWORDS = [
        'xss' => ['script', 'javascript', 'onerror', 'onload', 'onclick', 'onmouseover', 'alert', 'eval', 'document', 'cookie', 'window', 'location'],
        'sql' => ['select', 'union', 'insert', 'update', 'delete', 'drop', 'from', 'where', 'order', 'group', 'having', 'concat', 'substring', 'database', 'table', 'column'],
        'command' => ['exec', 'system', 'shell', 'cmd', 'bash', 'powershell', 'wget', 'curl', 'nc', 'netcat', 'chmod', 'chown', 'sudo', 'passwd'],
        'path' => ['etc', 'passwd', 'shadow', 'hosts', 'proc', 'boot', 'win', 'ini'],
        'template' => ['render', 'template', 'jinja', 'mustache', 'handlebars', 'ejs', 'pug', 'twig'],
    ];

    private const ATTACK_STRUCTURES = [
        'tag_like' => '<[^>]+>',
        'function_call' => '\w{1,64}\s*\([^)]{0,256}\)',
        'command_chain' => '[;&|]{1,2}',
        'path_traversal' => '\\.{2,20}[/\\\\]',
        'url_pattern' => '[a-z]{1,32}://',
    ];

    public static function looksLikeBinaryContent(string $content): bool
    {
        if ($content === '') {
            return false;
        }
        // Single linear pass over bytes decoding UTF-8 manually (invalid
        // bytes decode to U+FFFD, one code point per byte, mirroring the
        // mbstring-based Text helpers). The previous per-code-point
        // Text::slice/ord loop was O(n^2) through mb_strcut and burned
        // minutes on binary bodies.
        $n = strlen($content);
        $total = 0;
        $nonText = 0;
        $i = 0;
        while ($i < $n) {
            $byte = ord($content[$i]);
            if ($byte < 0x80) {
                $cp = $byte;
                $size = 1;
            } elseif ($byte >= 0xc2 && $byte <= 0xdf && $i + 1 < $n && self::isContinuationByte($content, $i + 1)) {
                $cp = (($byte & 0x1f) << 6) | (ord($content[$i + 1]) & 0x3f);
                $size = 2;
            } elseif ($byte >= 0xe0 && $byte <= 0xef && $i + 2 < $n && self::isContinuationByte($content, $i + 1) && self::isContinuationByte($content, $i + 2)) {
                $cp = (($byte & 0x0f) << 12) | ((ord($content[$i + 1]) & 0x3f) << 6) | (ord($content[$i + 2]) & 0x3f);
                $size = 3;
            } elseif ($byte >= 0xf0 && $byte <= 0xf4 && $i + 3 < $n && self::isContinuationByte($content, $i + 1) && self::isContinuationByte($content, $i + 2) && self::isContinuationByte($content, $i + 3)) {
                $cp = (($byte & 0x07) << 18) | ((ord($content[$i + 1]) & 0x3f) << 12) | ((ord($content[$i + 2]) & 0x3f) << 6) | (ord($content[$i + 3]) & 0x3f);
                $size = 4;
            } else {
                $cp = 0xfffd;
                $size = 1;
            }
            if ($size === 2 && $cp < 0x80) {
                $cp = 0xfffd;
            }
            if ($size === 3 && ($cp < 0x800 || ($cp >= 0xd800 && $cp <= 0xdfff))) {
                $cp = 0xfffd;
            }
            if ($size === 4 && ($cp < 0x10000 || $cp > 0x10ffff)) {
                $cp = 0xfffd;
            }
            $total++;
            if ($cp !== 9 && $cp !== 10 && $cp !== 13
                && (!Text::isprintableCp($cp) || $cp === 0xfffd)) {
                $nonText++;
            }
            $i += $size;
        }

        return $nonText / $total >= self::BINARY_CONTENT_RATIO_THRESHOLD;
    }

    private static function isContinuationByte(string $content, int $i): bool
    {
        $byte = ord($content[$i]);

        return $byte >= 0x80 && $byte <= 0xbf;
    }

    private static function tagScanWindow(string $content): string
    {
        $idx = mb_strrpos($content, '>', 0, 'UTF-8');

        return $idx === false ? '' : Text::slice($content, 0, $idx + 1);
    }

    public static function extractTokens(string $content): array
    {
        if (Text::len($content) > self::MAX_TOKEN_CONTENT_LENGTH) {
            $content = Text::slice($content, 0, self::MAX_TOKEN_CONTENT_LENGTH);
        }
        $content = preg_replace(Preg::compile('\\s+'), ' ', $content) ?? $content;
        $lower = mb_strtolower($content, 'UTF-8');
        $tokens = [];
        foreach (Preg::allMatches('\\b\\w+\\b', $lower) as $m) {
            $tokens[] = $m['text'];
            if (count($tokens) >= self::MAX_TOKENS) {
                break;
            }
        }
        $specialPatterns = [];
        foreach (self::ATTACK_STRUCTURES as $name => $pattern) {
            $scanContent = $name === 'tag_like' ? self::tagScanWindow($content) : $content;
            $count = 0;
            foreach (Preg::allMatches($pattern, $scanContent) as $m) {
                $specialPatterns[] = $m['text'];
                $count++;
                if ($count >= 10) {
                    break;
                }
            }
            if (count($specialPatterns) >= 50) {
                break;
            }
        }

        return array_slice(array_merge($tokens, $specialPatterns), 0, self::MAX_TOKENS);
    }

    public static function calculateEntropy(string $content): float
    {
        if ($content === '') {
            return 0.0;
        }
        if (Text::len($content) > self::MAX_ENTROPY_LENGTH) {
            $content = Text::slice($content, 0, self::MAX_ENTROPY_LENGTH);
        }
        $counts = [];
        $n = Text::len($content);
        for ($i = 0; $i < $n; $i++) {
            $ch = Text::slice($content, $i, 1);
            $counts[$ch] = ($counts[$ch] ?? 0) + 1;
        }
        $entropy = 0.0;
        foreach ($counts as $count) {
            $probability = $count / $n;
            if ($probability > 0) {
                $entropy -= $probability * log($probability, 2);
            }
        }

        return $entropy;
    }

    public static function detectEncodingLayers(string $content): int
    {
        if (Text::len($content) > self::MAX_SCAN_LENGTH) {
            $content = Text::slice($content, 0, self::MAX_SCAN_LENGTH);
        }
        $layers = 0;
        if (Preg::hasMatch('%[0-9a-fA-F]{2}', $content)) {
            $layers++;
        }
        if (Preg::hasMatch('[A-Za-z0-9+/]{4,}={0,2}', $content)) {
            $layers++;
        }
        if (Preg::hasMatch('(?:0x)?[0-9a-fA-F]{4,}', $content)) {
            $layers++;
        }
        if (Preg::hasMatch('\\\\u[0-9a-fA-F]{4}', $content)) {
            $layers++;
        }
        if (Preg::hasMatch('&[#\\w]+;', $content)) {
            $layers++;
        }

        return $layers;
    }

    private static function getStructuralPatternBoost(string $attackType, string $content): float
    {
        $checks = [
            'xss' => [self::ATTACK_STRUCTURES['tag_like'], false],
            'sql' => ['\\b(?:union|select|from|where)\\b', true],
            'command' => ['[;&|]', false],
            'path' => [self::ATTACK_STRUCTURES['path_traversal'], false],
        ];
        if (!isset($checks[$attackType])) {
            return 0.0;
        }
        [$pattern, $ignoreCase] = $checks[$attackType];
        $scanContent = $attackType === 'xss' ? self::tagScanWindow($content) : $content;

        return Preg::hasMatch($pattern, $scanContent, $ignoreCase) ? 0.3 : 0.0;
    }

    public static function attackProbabilitiesForTokens(array $tokenSet, string $content): array
    {
        $probabilities = [];
        foreach (self::ATTACK_KEYWORDS as $attackType => $keywords) {
            $matches = count(array_intersect($tokenSet, $keywords));
            $baseScore = count($keywords) > 0 ? $matches / count($keywords) : 0.0;
            $score = $baseScore + self::getStructuralPatternBoost($attackType, $content);
            $probabilities[$attackType] = min($score, 1.0);
        }

        return $probabilities;
    }

    public static function detectObfuscation(string $content): bool
    {
        if (self::looksLikeBinaryContent($content)) {
            return false;
        }
        if (self::calculateEntropy($content) > 4.5) {
            return true;
        }
        if (self::detectEncodingLayers($content) > 2) {
            return true;
        }
        $specialCount = 0;
        foreach (Preg::allMatches('[^a-zA-Z0-9\\s]', $content) as $ignored) {
            $specialCount++;
        }
        $len = max(Text::len($content), 1);
        if ($specialCount / $len > 0.4) {
            return true;
        }

        return Preg::hasMatch('\\S{100,}', $content);
    }

    public static function extractSuspiciousPatterns(string $content): array
    {
        $patterns = [];
        $contentLen = Text::len($content);
        foreach (self::ATTACK_STRUCTURES as $name => $pattern) {
            $scanContent = $name === 'tag_like' ? self::tagScanWindow($content) : $content;
            foreach (Preg::allMatches($pattern, $scanContent) as $m) {
                $cpStart = Text::bytesToCp($scanContent, $m['start']);
                $cpEnd = Text::bytesToCp($scanContent, $m['end']);
                $contextStart = max(0, $cpStart - 20);
                $contextEnd = min($contentLen, $cpEnd + 20);
                $patterns[] = [
                    'type' => $name,
                    'pattern' => $m['text'],
                    'position' => $cpStart,
                    'context' => Text::slice($content, $contextStart, $contextEnd - $contextStart),
                ];
            }
        }

        return $patterns;
    }

    private static function checkCodePatternRisks(string $content): float
    {
        $risk = 0.0;
        if (Preg::hasMatch('[\\{\\}].*[\\{\\}]', $content)) {
            $risk += 0.2;
        }
        if (Preg::hasMatch(self::ATTACK_STRUCTURES['function_call'], $content)) {
            $risk += 0.2;
        }
        if (Preg::hasMatch('[$@]\\w+', $content)) {
            $risk += 0.1;
        }
        if (Preg::hasMatch('[=+\\-*/]{2,}', $content)) {
            $risk += 0.1;
        }

        return $risk;
    }

    private static function checkAstParsingRisk(string $content): float
    {
        if (Text::len($content) > self::MAX_AST_LENGTH) {
            return 0.0;
        }

        return 0.0;
    }

    private static function checkInjectionKeywords(string $content): float
    {
        foreach (['eval', 'exec', 'compile', '__import__', 'globals', 'locals'] as $keyword) {
            if (Preg::hasMatch('\\b' . $keyword . '\\b', $content)) {
                return 0.2;
            }
        }

        return 0.0;
    }

    public static function analyzeCodeInjectionRisk(string $content): float
    {
        $risk = self::checkCodePatternRisks($content);
        $risk += self::checkAstParsingRisk($content);
        $risk += self::checkInjectionKeywords($content);

        return min($risk, 1.0);
    }

    public static function analyze(string $content): array
    {
        $tokens = self::extractTokens($content);

        return [
            'attack_probabilities' => self::attackProbabilitiesForTokens(array_values(array_unique($tokens)), $content),
            'entropy' => self::calculateEntropy($content),
            'encoding_layers' => self::detectEncodingLayers($content),
            'is_obfuscated' => self::detectObfuscation($content),
            'suspicious_patterns' => self::extractSuspiciousPatterns($content),
            'code_injection_risk' => self::analyzeCodeInjectionRisk($content),
            'token_count' => count($tokens),
        ];
    }

    public static function getThreatScore(array $analysisResults): float
    {
        $score = 0.0;
        $attackProbs = $analysisResults['attack_probabilities'] ?? [];
        if ($attackProbs !== []) {
            $score += max($attackProbs) * 0.3;
        }
        if ($analysisResults['is_obfuscated'] ?? false) {
            $score += 0.2;
        }
        $encodingLayers = $analysisResults['encoding_layers'] ?? 0;
        if ($encodingLayers > 0) {
            $score += min($encodingLayers * 0.1, 0.2);
        }
        $score += ($analysisResults['code_injection_risk'] ?? 0.0) * 0.2;
        $patterns = $analysisResults['suspicious_patterns'] ?? [];
        if ($patterns !== []) {
            $score += min(count($patterns) * 0.05, 0.1);
        }

        return min($score, 1.0);
    }
}
