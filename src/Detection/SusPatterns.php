<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Detection;

use RenzoFranceschini\GuardCore\Support\Generated\PatternData;
use RenzoFranceschini\GuardCore\Support\Text;

final class SusPatterns
{
    private const EMBEDDED_JSON_LEAF_CONTEXT_SUFFIX = ':embedded_json';
    private const KNOWN_CONTEXTS = ['query_param', 'header', 'url_path', 'request_body', 'unknown'];
    private const COMPILER_TIMEOUT = 2.0;
    private const MAX_CONTENT_LENGTH = 10000;

    private const LDAP_NULL_BYTE_ATTR_TAIL = '\\*\\)+(?:%00|\\\\u0000|\\\\x00|\\\\0|\\x00)';
    private const LDAP_NULL_BYTE_DECODED_ATTR_TAIL = '\\*\\)+\\x00';

    private Preprocessor $preprocessor;
    private float $semanticThreshold;

    public function __construct(float $semanticThreshold = 0.7)
    {
        $this->preprocessor = new Preprocessor();
        $this->semanticThreshold = $semanticThreshold;
    }

    public static function normalizeContext(?string $context): string
    {
        if ($context === null) {
            return 'unknown';
        }
        $normalized = explode(':', $context, 2)[0];

        return in_array($normalized, self::KNOWN_CONTEXTS, true) ? $normalized : 'unknown';
    }

    public static function resolvePatternWeight(string $pattern, string $category): float
    {
        if (isset(PatternData::WEIGHT_OVERRIDES[$pattern])) {
            return PatternData::WEIGHT_OVERRIDES[$pattern];
        }

        return 1.0;
    }

    private static function isRawViewSource(string $source): bool
    {
        return in_array($source, PatternData::RAW_VIEW_SOURCES, true);
    }

    private static function isUrlDecodedViewSource(string $source): bool
    {
        return in_array($source, PatternData::URL_DECODED_VIEW_SOURCES, true);
    }

    private static function patternExcludedFromView(string $source, string $viewMode): bool
    {
        if ($viewMode === 'raw') {
            return self::isUrlDecodedViewSource($source) || !self::isRawViewSource($source);
        }
        if ($viewMode === 'url_decoded') {
            return self::isRawViewSource($source) || !self::isUrlDecodedViewSource($source);
        }
        if ($viewMode === 'processed') {
            return self::isRawViewSource($source) || self::isUrlDecodedViewSource($source);
        }

        return false;
    }

    public static function sanitizeForReporting(string $value): string
    {
        $out = '';
        $len = Text::len($value);
        for ($i = 0; $i < $len; $i++) {
            $ch = Text::slice($value, $i, 1);
            $cp = Text::ord($ch);
            if ($cp >= 0xdc80 && $cp <= 0xdcff) {
                $out .= '\\x' . str_pad(dechex($cp - 0xdc00), 2, '0', STR_PAD_LEFT);
                continue;
            }
            $out .= $ch;
        }

        return $out;
    }

    private function buildRegexThreat(string $source, array $match, string $category, string $content, string $validatorContext): ?array
    {
        $kind = PatternData::VALIDATOR_KINDS[$source] ?? null;
        if ($kind !== null && !self::validatorAccepts($kind, $content, $match, $validatorContext, $source)) {
            return null;
        }

        return [
            'type' => 'regex',
            'pattern' => $source,
            'match' => self::sanitizeForReporting($match['text']),
            'position' => Text::bytesToCp($content, $match['start']),
            'category' => $category,
            'weight' => self::resolvePatternWeight($source, $category),
        ];
    }

    private static function validatorAccepts(string $kind, string $content, array $match, string $context, string $source): bool
    {
        return match ($kind) {
            'legacy_ipv4' => LdapIpv4::legacyIpv4MatchIsBlocked($match),
            'ldap_wildcard_chain' => LdapIpv4::wildcardChainIsInjection($content, $match, $source),
            'ldap_paren_conjunction' => LdapIpv4::parenConjunctionIsInjection($content, $match, $source),
            'glued_backtick' => ShellValidators::gluedBacktickPairIsInjection($content, $match, $context),
            'source_extension_path' => !str_ends_with($context, self::EMBEDDED_JSON_LEAF_CONTEXT_SUFFIX),
            'dollar_substitution' => ShellValidators::dollarSubstitutionPairIsInjection($content, $match, $context),
            'brace_expansion' => ShellValidators::braceExpansionIsDangerousCommand($content, $match),
            'quote_splice' => ShellValidators::quoteSpliceTokenIsDangerousCommand($content, $match),
            'glob' => ShellValidators::globWildcardTokenIsDangerousCommand($content, $match, $context),
            'pickle_generic' => Pickle::globalCandidateIsInjection($content, $match),
            default => true,
        };
    }

    private static function fileUploadKind(string $source): string
    {
        if (str_contains($source, '%00|')) {
            return 'file_upload_truncation';
        }
        if (str_contains($source, '(?:\\x00|;)')) {
            return 'file_upload_decoded_truncation';
        }
        if (str_contains($source, 'docx')) {
            return 'file_upload_double';
        }

        return 'file_upload_dangerous';
    }

    private static function matchesForPattern(string $source, string $content): array
    {
        $matcherKind = PatternData::MATCHER_KINDS[$source] ?? null;
        if ($matcherKind !== null) {
            return match ($matcherKind) {
                'load_file' => Matchers::loadFileScanMatches($content, $source),
                'cmd_dollar' => Matchers::cmdInjectionDollarScanMatches($content, $source),
                'file_upload' => Matchers::fileUploadScanMatches($content, self::fileUploadKind($source)),
                'template_curly_keyword' => Matchers::templateKeywordMatches($content, $source, '{{', '}}'),
                'template_dollar' => Matchers::templateExpressionMatches($content, $source, 'dollar'),
                'template_curly_call' => Matchers::templateExpressionMatches($content, $source, 'curly'),
                'template_percent' => Matchers::templateKeywordMatches($content, $source, '{%', '%}'),
                'template_asp' => Matchers::templateExpressionMatches($content, $source, 'asp'),
                'template_hash' => Matchers::templateExpressionMatches($content, $source, 'hash'),
                'glob' => Matchers::globWildcardScanMatches($content, $source),
                default => Preg::allMatches($source, $content),
            };
        }

        $finderKind = PatternData::FINDER_KINDS[$source] ?? null;
        if ($finderKind !== null) {
            return match ($finderKind) {
                'shell_dash_c' => Matchers::cmdInjectionShellDashCFinditer($content, $source),
                'ldap_null_attr_raw' => Matchers::ldapNullByteAttrFinditer($content, $source, self::LDAP_NULL_BYTE_ATTR_TAIL),
                'ldap_null_attr_decoded' => Matchers::ldapNullByteAttrFinditer($content, $source, self::LDAP_NULL_BYTE_DECODED_ATTR_TAIL),
                'quote_splice' => Matchers::quoteSpliceFinditer($content, $source),
                'pickle_generic' => Matchers::pickleGlobalGenericFinditer($content, $source),
                'xml_public_dtd' => XmlXxe::xmlXxePublicExternalDtdFinditer($content, $source),
                default => Preg::allMatches($source, $content),
            };
        }

        $bounds = PatternData::SCAN_WINDOW_BOUNDS[$source] ?? null;
        if ($bounds !== null) {
            if ($source === '<!(?:ENTITY|DOCTYPE)[^>]+SYSTEM[^>]+>') {
                return XmlXxe::xmlSystemFinditer($content);
            }
            if ($source === '<!DOCTYPE[^>\\[]*\\[[\\s\\S]*?<!ENTITY') {
                return XmlXxe::xmlInternalEntityFinditer($content);
            }
            $matches = [];
            foreach ($bounds as [$prefix, $terminator]) {
                foreach (Matchers::boundedFindIter($content, $source, $prefix, $terminator) as $m) {
                    $matches[] = $m;
                }
            }

            return $matches;
        }

        return Preg::allMatches($source, $content);
    }

    private function firstAcceptedRegexThreat(string $source, string $content, string $category, string $validatorContext): ?array
    {
        foreach (self::matchesForPattern($source, $content) as $match) {
            $threat = $this->buildRegexThreat($source, $match, $category, $content, $validatorContext);
            if ($threat !== null) {
                return $threat;
            }
        }

        return null;
    }

    private function checkRegexPatterns(string $content, string $context, string $viewMode): array
    {
        $threats = [];
        $matchedPatterns = [];
        $timeouts = [];
        $normalized = self::normalizeContext($context);
        $validatorContext = str_ends_with($context, self::EMBEDDED_JSON_LEAF_CONTEXT_SUFFIX)
            ? $normalized . self::EMBEDDED_JSON_LEAF_CONTEXT_SUFFIX
            : $normalized;
        $skipFilter = $normalized === 'unknown' || $normalized === 'request_body';

        foreach (PatternData::PATTERNS as [$source, $contexts, $category]) {
            if (self::patternExcludedFromView($source, $viewMode)) {
                continue;
            }
            if (!$skipFilter && !in_array($normalized, $contexts, true)) {
                continue;
            }
            $start = microtime(true);
            $threat = $this->firstAcceptedRegexThreat($source, $content, $category, $validatorContext);
            if ($threat === null && (microtime(true) - $start) >= 0.9 * self::COMPILER_TIMEOUT) {
                $timeouts[] = $source;
            }
            if ($threat !== null) {
                $threats[] = $threat;
                $matchedPatterns[] = $source;
            }
        }

        return [$threats, $matchedPatterns, $timeouts];
    }

    private function checkDecodedViewPathTraversal(string $processedContent, string $content, string $context): ?array
    {
        $rawViewContent = $this->preprocessor->preprocessSignalPreserving($content);
        $decodedViewContent = $processedContent;
        $decodedMatches = Preg::allMatches(PatternData::DECODED_PATH_TRAVERSAL_RE, $decodedViewContent);
        $rawCount = count(Preg::allMatches(PatternData::DECODED_PATH_TRAVERSAL_RE, $rawViewContent));
        if (count($decodedMatches) <= $rawCount) {
            return null;
        }
        $match = $decodedMatches[0];

        return [
            'type' => 'regex',
            'pattern' => PatternData::DECODED_PATH_TRAVERSAL_RE,
            'match' => self::sanitizeForReporting($match['text']),
            'position' => Text::bytesToCp($decodedViewContent, $match['start']),
            'category' => 'path_traversal',
            'weight' => self::resolvePatternWeight(PatternData::DECODED_PATH_TRAVERSAL_RE, 'path_traversal'),
        ];
    }

    private function checkUrlDecodedViewPatterns(string $content, string $context, string $precomputedDecoded, array|bool $decodeBudgetExhausted): array
    {
        $urlDecodedViewContent = Truncation::truncateSafely($precomputedDecoded, $this->preprocessor);
        [$threats, $matched, $timeouts] = $this->checkRegexPatterns($urlDecodedViewContent, $context, 'url_decoded');

        return [$threats, $matched, $timeouts, $decodeBudgetExhausted];
    }

    private function checkShortBase64AdditiveViewPatterns(string $content, string $context): array
    {
        $additiveViewContent = $this->preprocessor->preprocessShortBase64AdditiveView($content);
        if ($additiveViewContent === '') {
            return [[], [], []];
        }

        return $this->checkRegexPatterns($additiveViewContent, $context, 'all');
    }

    private function checkSemanticThreats(string $content, string $rawContent): array
    {
        if (Semantic::looksLikeBinaryContent($rawContent)) {
            return [[], 0.0];
        }
        $semanticBudget = min(Text::len($content), self::MAX_CONTENT_LENGTH);
        $analysis = Semantic::analyze(Text::slice($content, 0, $semanticBudget));
        $semanticScore = Semantic::getThreatScore($analysis);
        $threats = [];
        if ($semanticScore > $this->semanticThreshold) {
            foreach ($analysis['attack_probabilities'] as $attackType => $probability) {
                if ($probability >= $this->semanticThreshold) {
                    $threats[] = [
                        'type' => 'semantic',
                        'attack_type' => $attackType,
                        'probability' => $probability,
                        'analysis' => $analysis,
                    ];
                }
            }
            if ($threats === [] && $semanticScore >= $this->semanticThreshold) {
                $threats[] = [
                    'type' => 'semantic',
                    'attack_type' => 'suspicious',
                    'threat_score' => $semanticScore,
                    'analysis' => $analysis,
                ];
            }
        }

        return [$threats, $semanticScore];
    }

    public function detect(string $content, string $ip, string $context): array
    {
        $originalContent = $content;
        $decodeBudgetExhausted = [false];
        [$processedContent, $precomputedDecoded] = $this->preprocessor->preprocessWithDecoded($content, $decodeBudgetExhausted);

        [$regexThreats, $matchedPatterns, $timeouts] = $this->checkRegexPatterns($processedContent, $context, 'processed');

        $rawViewContent = $this->preprocessor->preprocessSignalPreserving($content);
        [$rawThreats, $rawMatched, $rawTimeouts] = $this->checkRegexPatterns($rawViewContent, $context, 'raw');
        $regexThreats = array_merge($regexThreats, $rawThreats);
        $matchedPatterns = array_merge($matchedPatterns, $rawMatched);
        $timeouts = array_merge($timeouts, $rawTimeouts);

        $decodedViewThreat = $this->checkDecodedViewPathTraversal($processedContent, $content, $context);
        if ($decodedViewThreat !== null) {
            $regexThreats[] = $decodedViewThreat;
            $matchedPatterns[] = $decodedViewThreat['pattern'];
        }

        [$urlDecodedThreats, $urlDecodedMatched, $urlDecodedTimeouts, $urlDecodedBudgetExhausted] =
            $this->checkUrlDecodedViewPatterns($content, $context, $precomputedDecoded, $decodeBudgetExhausted);
        $regexThreats = array_merge($regexThreats, $urlDecodedThreats);
        $matchedPatterns = array_merge($matchedPatterns, $urlDecodedMatched);
        $timeouts = array_merge($timeouts, $urlDecodedTimeouts);

        if ($decodeBudgetExhausted[0] || $urlDecodedBudgetExhausted[0]) {
            $exhaustionThreat = [
                'type' => 'regex',
                'pattern' => 'decode_budget_exhausted',
                'match' => 'decode_budget_exhausted',
                'position' => 0,
                'category' => 'custom',
                'weight' => 1.0,
            ];
            $regexThreats[] = $exhaustionThreat;
            $matchedPatterns[] = $exhaustionThreat['pattern'];
        }

        [$shortBase64Threats, $shortBase64Matched, $shortBase64Timeouts] = $this->checkShortBase64AdditiveViewPatterns($content, $context);
        $regexThreats = array_merge($regexThreats, $shortBase64Threats);
        $matchedPatterns = array_merge($matchedPatterns, $shortBase64Matched);
        $timeouts = array_merge($timeouts, $shortBase64Timeouts);

        [$semanticThreats] = $this->checkSemanticThreats($processedContent, $originalContent);

        $threats = array_merge($regexThreats, $semanticThreats);

        $anomaly = 0.0;
        foreach ($regexThreats as $t) {
            $anomaly += $t['weight'] ?? 1.0;
        }
        $isThreat = $anomaly >= 1.0 || count($semanticThreats) > 0;

        $semanticMax = 0.0;
        foreach ($semanticThreats as $t) {
            $semanticMax = max($semanticMax, $t['probability'] ?? $t['threat_score'] ?? 0.0);
        }
        $threatScore = ($regexThreats === [] && $semanticThreats === []) ? 0.0 : min(max($anomaly, $semanticMax), 1.0);

        usort($threats, self::canonicalThreatSort(...));

        return [
            'is_threat' => $isThreat,
            'threat_score' => round($threatScore, 6),
            'threats' => $threats,
            'original_length' => Text::len($originalContent),
            'processed_length' => Text::len($processedContent),
            'detection_method' => 'enhanced',
        ];
    }

    public static function canonicalThreatSort(array $a, array $b): int
    {
        $categoryA = $a['category'] ?? $a['attack_type'] ?? '';
        $categoryB = $b['category'] ?? $b['attack_type'] ?? '';
        $ka = [$categoryA, $a['pattern'] ?? '', $a['position'] ?? 0, $a['type'] ?? ''];
        $kb = [$categoryB, $b['pattern'] ?? '', $b['position'] ?? 0, $b['type'] ?? ''];

        return $ka <=> $kb;
    }
}
