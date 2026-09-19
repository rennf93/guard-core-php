<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Config;

use RenzoFranceschini\GuardCore\Ip\CanonicalIp;

final class SecurityConfig
{
    public const VALID_BYPASS_CHECKS = ['all', 'ip_ban', 'ip', 'clouds', 'rate_limit', 'penetration'];

    public const CHECK_NAME_VALUES = [
        'route_config', 'emergency_mode', 'https_enforcement', 'request_logging',
        'request_size_content', 'required_headers', 'authentication', 'referrer',
        'custom_validators', 'time_window', 'cloud_ip_refresh', 'ip_security',
        'cloud_provider', 'user_agent', 'rate_limit', 'suspicious_activity',
        'custom_request',
    ];

    public const DETECTION_CATEGORIES = [
        'xss', 'sqli', 'dir_traversal', 'path_traversal', 'cmd_injection',
        'file_inclusion', 'ldap', 'xml', 'ssrf', 'nosql', 'file_upload',
        'template', 'http_split', 'sensitive_file', 'cms_probing', 'recon',
        'proto_pollution', 'code_injection', 'deserialization',
    ];

    public const DEFAULT_EXCLUDE_PATHS = [
        '/docs', '/redoc', '/openapi.json', '/openapi.yaml', '/favicon.ico', '/static',
    ];

    private int $revision = 0;

    public readonly bool $enableRedis;

    public readonly string $redisUrl;

    public readonly string $redisPrefix;

    public readonly bool $redisFailOpen;

    public readonly bool $passiveMode;

    public readonly bool $failSecure;

    public readonly bool $routeResolutionStrict;

    /** @var list<string> */
    public readonly array $trustedProxies;

    public readonly int $trustedProxyDepth;

    public readonly bool $trustXForwardedProto;

    /** @var list<string>|null */
    public readonly ?array $whitelist;

    /** @var list<string> */
    public readonly array $blacklist;

    public readonly bool $enableIpBanning;

    public readonly int $autoBanThreshold;

    public readonly int $autoBanDuration;

    /** @var array<string, array{threshold: int, duration: int}> */
    public readonly array $threatBanConfig;

    public readonly bool $enableRateLimitAutoBan;

    public readonly bool $enableRateLimiting;

    public readonly int $rateLimit;

    public readonly int $rateLimitWindow;

    /** @var array<string, array{limit: int, window: int}> */
    public readonly array $endpointRateLimits;

    public readonly bool $enablePenetrationDetection;

    /** @var array<string, true> */
    public readonly array $enabledDetectionCategories;

    public readonly float $detectionSemanticThreshold;

    /** @var list<string> */
    public readonly array $excludePaths;

    /** @var array<string, true> */
    public readonly array $mutedCheckLogs;

    /** @var array<string, true> */
    public readonly array $logSensitiveHeaders;

    /** @var array<string, true> */
    public readonly array $logSensitiveParams;

    /** @var array<string, true> */
    public readonly array $logSensitiveBodyFields;

    /** @var array<int, string> */
    public readonly array $customErrorResponses;

    /** @var list<string> */
    public readonly array $emergencyWhitelist;

    public readonly bool $emergencyMode;

    public readonly bool $enforceHttps;

    /** @var list<string> */
    public readonly array $blockedUserAgents;

    /** @var (\Closure(object, string): mixed)|null */
    public readonly ?\Closure $authVerifier;

    /** @var (\Closure(object, array<string, mixed>): void)|null */
    public readonly ?\Closure $onBlock;

    /**
     * Supported-subset constructor. Any option belonging to a section-02
     * feature this port does not implement yet, when set to an enabling
     * value, throws UnsupportedFeatureError (fail closed).
     *
     * @param list<string>|null $whitelist
     * @param list<string> $blacklist
     * @param list<string> $trustedProxies
     * @param array<string, array{threshold: int, duration: int}> $threatBanConfig
     * @param array<string, array{limit: int, window: int}> $endpointRateLimits
     * @param list<string>|null $enabledDetectionCategories null = all categories
     * @param list<string> $excludePaths
     * @param list<string> $mutedCheckLogs
     * @param list<string> $logSensitiveHeaders
     * @param list<string> $logSensitiveParams
     * @param list<string> $logSensitiveBodyFields
     * @param (\Closure(object, array<string, mixed>): void)|null $onBlock
     * @param list<string> $emergencyWhitelist
     * @param array<int, string> $customErrorResponses per-status-code body overrides
     * @param list<string> $blockedUserAgents regex patterns, subject truncated to 512 chars
     * @param list<string> $blockedCountries unsupported when non-empty
     * @param list<string> $blockedCountries unsupported when non-empty
     * @param list<string> $whitelistCountries unsupported when non-empty
     * @param list<string> $blockCloudProviders unsupported when non-empty
     */
    public function __construct(
        ?bool $enableRedis = null,
        string $redisUrl = 'redis://localhost:6379',
        string $redisPrefix = 'guard_core:',
        ?bool $redisFailOpen = null,
        ?bool $passiveMode = null,
        ?bool $failSecure = null,
        ?bool $routeResolutionStrict = null,
        ?array $trustedProxies = null,
        ?int $trustedProxyDepth = null,
        ?bool $trustXForwardedProto = null,
        ?array $whitelist = null,
        ?array $blacklist = null,
        ?bool $enableIpBanning = null,
        ?int $autoBanThreshold = null,
        ?int $autoBanDuration = null,
        ?array $threatBanConfig = null,
        ?bool $enableRateLimitAutoBan = null,
        ?bool $enableRateLimiting = null,
        ?int $rateLimit = null,
        ?int $rateLimitWindow = null,
        ?array $endpointRateLimits = null,
        ?bool $enablePenetrationDetection = null,
        ?array $enabledDetectionCategories = null,
        ?float $detectionSemanticThreshold = null,
        ?array $excludePaths = null,
        ?array $mutedCheckLogs = null,
        ?array $logSensitiveHeaders = null,
        ?array $logSensitiveParams = null,
        ?array $logSensitiveBodyFields = null,
        ?\Closure $onBlock = null,
        array $blockedCountries = [],
        array $whitelistCountries = [],
        array $blockCloudProviders = [],
        ?bool $emergencyMode = null,
        ?array $emergencyWhitelist = null,
        ?bool $enforceHttps = null,
        ?array $customErrorResponses = null,
        ?array $blockedUserAgents = null,
        ?bool $enableCors = null,
        ?bool $enableAgent = null,
        ?bool $enableDynamicRules = null,
        ?\Closure $customRequestCheck = null,
        ?\Closure $authVerifier = null
    ) {
        $this->enableRedis = $enableRedis ?? true;
        $this->redisUrl = $redisUrl;
        $this->redisPrefix = $redisPrefix;
        $this->redisFailOpen = $redisFailOpen ?? false;
        $this->passiveMode = $passiveMode ?? false;
        $this->failSecure = $failSecure ?? true;
        $this->routeResolutionStrict = $routeResolutionStrict ?? false;
        $this->trustedProxies = $this->validateIpCidrList($trustedProxies ?? [], 'trusted_proxies');
        $this->trustedProxyDepth = $trustedProxyDepth ?? 1;
        if ($this->trustedProxyDepth < 1) {
            throw new \InvalidArgumentException('trusted_proxy_depth must be >= 1');
        }
        $this->trustXForwardedProto = $trustXForwardedProto ?? false;
        $this->whitelist = $whitelist === null ? null : $this->validateIpCidrList($whitelist, 'whitelist');
        $this->blacklist = $this->validateIpCidrList($blacklist ?? [], 'blacklist');
        $this->enableIpBanning = $enableIpBanning ?? true;
        $this->autoBanThreshold = $autoBanThreshold ?? 10;
        if ($this->autoBanThreshold < 1) {
            throw new \InvalidArgumentException('auto_ban_threshold must be >= 1');
        }
        $this->autoBanDuration = $autoBanDuration ?? 3600;
        if ($this->autoBanDuration < 1) {
            throw new \InvalidArgumentException('auto_ban_duration must be >= 1');
        }
        $this->threatBanConfig = $this->validateThreatBanConfig($threatBanConfig ?? []);
        $this->enableRateLimitAutoBan = $enableRateLimitAutoBan ?? false;
        $this->enableRateLimiting = $enableRateLimiting ?? true;
        $this->rateLimit = $rateLimit ?? 10;
        $this->rateLimitWindow = $rateLimitWindow ?? 60;
        $this->endpointRateLimits = $this->validateEndpointRateLimits($endpointRateLimits ?? []);
        $this->enablePenetrationDetection = $enablePenetrationDetection ?? true;
        $this->enabledDetectionCategories = $this->validateDetectionCategories($enabledDetectionCategories);
        $this->detectionSemanticThreshold = $detectionSemanticThreshold ?? 0.7;
        if ($this->detectionSemanticThreshold < 0.0 || $this->detectionSemanticThreshold > 1.0) {
            throw new \InvalidArgumentException('detection_semantic_threshold must be within [0.0, 1.0]');
        }
        $this->excludePaths = $this->validateExcludePaths($excludePaths ?? self::DEFAULT_EXCLUDE_PATHS);
        $this->mutedCheckLogs = $this->validateNameSet($mutedCheckLogs, self::CHECK_NAME_VALUES, 'muted_check_logs');
        $this->logSensitiveHeaders = $this->validateSensitiveSet($logSensitiveHeaders, 'log_sensitive_headers');
        $this->logSensitiveParams = $this->validateSensitiveSet($logSensitiveParams, 'log_sensitive_params');
        $this->logSensitiveBodyFields = $this->validateSensitiveSet($logSensitiveBodyFields, 'log_sensitive_body_fields');
        $this->onBlock = $onBlock;
        $this->customErrorResponses = $this->validateCustomErrorResponses($customErrorResponses ?? []);
        $this->emergencyWhitelist = $this->validateIpCidrList($emergencyWhitelist ?? [], 'emergency_whitelist');
        $this->emergencyMode = $emergencyMode ?? false;
        $this->enforceHttps = $enforceHttps ?? false;
        $this->blockedUserAgents = $this->validateBlockedUserAgents($blockedUserAgents ?? []);
        $this->authVerifier = $authVerifier;

        if ($blockedCountries !== [] || $whitelistCountries !== []) {
            throw new UnsupportedFeatureError('geo country blocking');
        }
        if ($blockCloudProviders !== []) {
            throw new UnsupportedFeatureError('cloud provider blocking');
        }
        if ($enableCors === true) {
            throw new UnsupportedFeatureError('CORS');
        }
        if ($enableAgent === true) {
            throw new UnsupportedFeatureError('guard agent telemetry');
        }
        if ($enableDynamicRules === true) {
            throw new UnsupportedFeatureError('dynamic rules');
        }
        if ($customRequestCheck !== null) {
            throw new UnsupportedFeatureError('custom_request_check');
        }
    }

    /** @param array<int, string> $map @return array<int, string> */
    private function validateCustomErrorResponses(array $map): array
    {
        $out = [];
        foreach ($map as $status => $message) {
            if (!is_int($status) || !is_string($message)) {
                throw new \InvalidArgumentException('custom_error_responses: map of int status => string body');
            }
            $out[$status] = $message;
        }

        return $out;
    }

    /** @param list<string> $patterns @return list<string> */
    private function validateBlockedUserAgents(array $patterns): array
    {
        $out = [];
        foreach ($patterns as $pattern) {
            if (!is_string($pattern) || $pattern === '') {
                throw new \InvalidArgumentException('blocked_user_agents: patterns must be non-empty strings');
            }
            $out[] = $pattern;
        }

        return $out;
    }

    public function revision(): int
    {
        return $this->revision;
    }

    /**
     * Replaces one or more config values (immutable-copy style) and bumps
     * the revision counter, mirroring SecurityConfig.__setattr__ semantics:
     * pipeline staleness detection observes the new revision.
     *
     * @param array<string, mixed> $values
     */
    public function with(array $values): self
    {
        $known = $this->constructorArgs();
        $args = [];
        foreach ($values as $name => $value) {
            $arg = self::fieldNameToArg($name);
            if (!array_key_exists($arg, $known)) {
                throw new \InvalidArgumentException("unknown config field '{$name}'");
            }
            $args[$arg] = $value;
            unset($known[$arg]);
        }

        $copy = new self(...$known, ...$args);
        $copy->revision = $this->revision + 1;

        return $copy;
    }

    /** @return array<string, mixed> */
    private function constructorArgs(): array
    {
        return [
            'enableRedis' => $this->enableRedis,
            'redisUrl' => $this->redisUrl,
            'redisPrefix' => $this->redisPrefix,
            'redisFailOpen' => $this->redisFailOpen,
            'passiveMode' => $this->passiveMode,
            'failSecure' => $this->failSecure,
            'routeResolutionStrict' => $this->routeResolutionStrict,
            'trustedProxies' => $this->trustedProxies,
            'trustedProxyDepth' => $this->trustedProxyDepth,
            'trustXForwardedProto' => $this->trustXForwardedProto,
            'whitelist' => $this->whitelist,
            'blacklist' => $this->blacklist,
            'enableIpBanning' => $this->enableIpBanning,
            'autoBanThreshold' => $this->autoBanThreshold,
            'autoBanDuration' => $this->autoBanDuration,
            'threatBanConfig' => $this->threatBanConfig,
            'enableRateLimitAutoBan' => $this->enableRateLimitAutoBan,
            'enableRateLimiting' => $this->enableRateLimiting,
            'rateLimit' => $this->rateLimit,
            'rateLimitWindow' => $this->rateLimitWindow,
            'endpointRateLimits' => $this->endpointRateLimits,
            'enablePenetrationDetection' => $this->enablePenetrationDetection,
            'enabledDetectionCategories' => array_keys($this->enabledDetectionCategories),
            'detectionSemanticThreshold' => $this->detectionSemanticThreshold,
            'excludePaths' => $this->excludePaths,
            'mutedCheckLogs' => array_keys($this->mutedCheckLogs),
            'logSensitiveHeaders' => array_keys($this->logSensitiveHeaders),
            'logSensitiveParams' => array_keys($this->logSensitiveParams),
            'logSensitiveBodyFields' => array_keys($this->logSensitiveBodyFields),
            'onBlock' => $this->onBlock,
            'customErrorResponses' => $this->customErrorResponses,
            'emergencyWhitelist' => $this->emergencyWhitelist,
            'emergencyMode' => $this->emergencyMode,
            'enforceHttps' => $this->enforceHttps,
            'blockedUserAgents' => $this->blockedUserAgents,
            'authVerifier' => $this->authVerifier,
        ];
    }

    private static function fieldNameToArg(string $field): string
    {
        $parts = explode('_', $field);

        return $parts[0] . implode('', array_map(ucfirst(...), array_slice($parts, 1)));
    }

    /** @param list<string> $entries @return list<string> */
    private function validateIpCidrList(array $entries, string $field): array
    {
        $out = [];
        foreach ($entries as $entry) {
            if (!is_string($entry) || $entry === '') {
                throw new \InvalidArgumentException("{$field}: entries must be non-empty IP or CIDR strings");
            }
            if (str_contains($entry, '/')) {
                try {
                    $out[] = CanonicalIp::canonicalNetwork($entry);
                } catch (\InvalidArgumentException $e) {
                    throw new \InvalidArgumentException("{$field}: invalid IP/CIDR entry '{$entry}': {$e->getMessage()}");
                }
            } else {
                $parsed = CanonicalIp::parse($entry);
                if ($parsed === null) {
                    throw new \InvalidArgumentException("{$field}: invalid IP/CIDR entry '{$entry}'");
                }
                $out[] = $parsed;
            }
        }

        return $out;
    }

    /** @param array<string, mixed> $config @return array<string, array{threshold: int, duration: int}> */
    private function validateThreatBanConfig(array $config): array
    {
        $valid = [...self::DETECTION_CATEGORIES, 'rate_limit'];
        $out = [];
        foreach ($config as $category => $entry) {
            if (!in_array($category, $valid, true)) {
                throw new \InvalidArgumentException("threat_ban_config: unknown category '{$category}'");
            }
            if (!is_array($entry) || !isset($entry['threshold'], $entry['duration'])) {
                throw new \InvalidArgumentException("threat_ban_config: '{$category}' needs threshold and duration");
            }
            $threshold = $entry['threshold'];
            $duration = $entry['duration'];
            if (!is_int($threshold) || $threshold < 1 || !is_int($duration) || $duration < 1) {
                throw new \InvalidArgumentException("threat_ban_config: '{$category}' threshold/duration must be ints >= 1");
            }
            $out[$category] = ['threshold' => $threshold, 'duration' => $duration];
        }

        return $out;
    }

    /** @param array<string, mixed> $limits @return array<string, array{limit: int, window: int}> */
    private function validateEndpointRateLimits(array $limits): array
    {
        $out = [];
        foreach ($limits as $endpoint => $entry) {
            if (!is_string($endpoint) || !is_array($entry) || !isset($entry['limit'], $entry['window'])) {
                throw new \InvalidArgumentException('endpoint_rate_limits: map of endpoint => {limit, window}');
            }
            $limit = $entry['limit'];
            $window = $entry['window'];
            if (!is_int($limit) || !is_int($window)) {
                throw new \InvalidArgumentException("endpoint_rate_limits: '{$endpoint}' limit/window must be ints");
            }
            $out[$endpoint] = ['limit' => $limit, 'window' => $window];
        }

        return $out;
    }

    /** @param list<string>|null $categories @return array<string, true> */
    private function validateDetectionCategories(?array $categories): array
    {
        if ($categories === null) {
            return array_fill_keys(self::DETECTION_CATEGORIES, true);
        }
        $out = [];
        foreach ($categories as $category) {
            if (!is_string($category) || !in_array($category, self::DETECTION_CATEGORIES, true)) {
                $name = is_string($category) ? $category : get_debug_type($category);
                throw new \InvalidArgumentException("enabled_detection_categories: unknown category '{$name}'");
            }
            $out[$category] = true;
        }

        return $out;
    }

    /** @param list<string> $paths @return list<string> */
    private function validateExcludePaths(array $paths): array
    {
        $out = [];
        foreach ($paths as $path) {
            if (!is_string($path)) {
                throw new \InvalidArgumentException('exclude_paths: entries must be strings');
            }
            $normalized = self::normalizeUrlPath($path);
            if ($normalized === null) {
                throw new \InvalidArgumentException("exclude_paths: entry '{$path}' fails URL normalization");
            }
            if ($normalized === '/' && $path !== '/') {
                throw new \InvalidArgumentException("exclude_paths: entry '{$path}' normalizes to '/'");
            }
            if ($normalized === '/') {
                continue;
            }
            $out[] = $normalized;
        }

        return $out;
    }

    public static function normalizeUrlPath(string $path): ?string
    {
        $decoded = $path;
        for ($i = 0; $i < 4; $i++) {
            $raw = $decoded;
            $decoded = urldecode($raw);
            if ($decoded === $raw) {
                break;
            }
            if (!preg_match('//u', $decoded)) {
                return null;
            }
        }
        $decoded = str_replace('\\', '/', $decoded);
        if (preg_match('/%(?![0-9A-Fa-f]{2})/', $decoded) === 1) {
            return null;
        }
        $segments = [];
        foreach (explode('/', $decoded) as $segment) {
            if ($segment === '.' || $segment === '') {
                continue;
            }
            if ($segment === '..') {
                if ($segments === []) {
                    return null;
                }
                array_pop($segments);
                continue;
            }
            if (str_contains($segment, ';')) {
                $segment = explode(';', $segment, 2)[0];
                if ($segment === '') {
                    continue;
                }
            }
            $segments[] = $segment;
        }

        return '/' . implode('/', $segments);
    }

    /**
     * @param list<string>|null $names
     * @param list<string> $vocabulary
     * @return array<string, true>
     */
    private function validateNameSet(?array $names, array $vocabulary, string $field): array
    {
        $out = [];
        foreach ($names ?? [] as $name) {
            if (!is_string($name) || !in_array($name, $vocabulary, true)) {
                $shown = is_string($name) ? $name : get_debug_type($name);
                throw new \InvalidArgumentException("{$field}: unknown name '{$shown}'");
            }
            $out[strtolower($name)] = true;
        }

        return $out;
    }

    /** @param list<string>|null $names @return array<string, true> */
    private function validateSensitiveSet(?array $names, string $field): array
    {
        if (is_string($names)) {
            throw new \InvalidArgumentException("{$field}: bare string rejected, pass a list of names");
        }
        $out = [];
        foreach ($names ?? [] as $name) {
            if (!is_string($name)) {
                throw new \InvalidArgumentException("{$field}: items must be strings");
            }
            $out[strtolower($name)] = true;
        }

        return $out;
    }

}
