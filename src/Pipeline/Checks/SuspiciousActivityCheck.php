<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Pipeline\Checks;

use RenzoFranceschini\GuardCore\Ban\IpBanManager;
use RenzoFranceschini\GuardCore\Config\SecurityConfig;
use RenzoFranceschini\GuardCore\Detection\BodyFormScan;
use RenzoFranceschini\GuardCore\Detection\JsonWalk;
use RenzoFranceschini\GuardCore\Detection\SusPatterns;
use RenzoFranceschini\GuardCore\Pipeline\SecurityCheck;
use RenzoFranceschini\GuardCore\Request\GuardRequest;
use RenzoFranceschini\GuardCore\Request\GuardResponse;
use RenzoFranceschini\GuardCore\Request\GuardResponseFactory;
use RenzoFranceschini\GuardCore\Routing\RouteResolver;

final class SuspiciousActivityCheck extends SecurityCheck
{
    private const MAX_TRACKED_IPS = 10000;

    /** @var array<string, int> */
    private array $suspiciousCounts = [];

    public function __construct(
        SecurityConfig $config,
        GuardResponseFactory $responseFactory,
        private readonly SusPatterns $susPatterns,
        private readonly ?IpBanManager $ipBanManager,
        private readonly RouteResolver $routeResolver
    ) {
        parent::__construct($config, $responseFactory);
    }

    public function checkName(): string
    {
        return 'suspicious_activity';
    }

    public function appliesTo(SecurityConfig $config, ?array $routeConfigs): bool
    {
        return $config->enablePenetrationDetection;
    }

    public function check(GuardRequest $request): ?GuardResponse
    {
        $clientIp = $request->state()->clientIp;
        if ($clientIp === null || $request->state()->isWhitelisted) {
            return null;
        }

        if ($this->routeResolver->shouldBypassCheck('penetration', $request->state()->routeConfig)) {
            return null;
        }

        $categories = [];
        foreach ($this->scanValues($request) as [$content, $context, $forcedCategory]) {
            if ($forcedCategory !== null) {
                // JSON mongo-operator keys report straight from the walk
                // (body_json_scan._mongo_operator_key_hit) without a pattern
                // scan.
                if (isset($this->config->enabledDetectionCategories[$forcedCategory])
                    && !in_array($forcedCategory, $categories, true)
                ) {
                    $categories[] = $forcedCategory;
                }
                continue;
            }
            $result = $this->susPatterns->detect($content, $clientIp, $context);
            if ($result['is_threat']) {
                foreach ($result['threats'] as $threat) {
                    $category = $threat['category'] ?? 'custom';
                    if (!in_array($category, $categories, true)
                        && isset($this->config->enabledDetectionCategories[$category])
                    ) {
                        $categories[] = $category;
                    }
                }
            }
        }

        if ($categories === []) {
            return null;
        }

        $triggerInfo = 'threat categories: ' . implode(',', $categories);
        $this->stashBlock($request, 'Penetration patterns detected', $triggerInfo);

        if ($this->isPassiveMode()) {
            return null;
        }

        if ($this->config->enableIpBanning) {
            $count = $this->incrementCount($clientIp);
            $threshold = $this->config->autoBanThreshold;
            $duration = $this->config->autoBanDuration;
            foreach ($categories as $category) {
                $entry = $this->config->threatBanConfig[$category] ?? null;
                if ($entry !== null) {
                    $threshold = $entry['threshold'];
                    $duration = $entry['duration'];
                    break;
                }
            }
            if ($count >= $threshold && $this->ipBanManager !== null) {
                $this->ipBanManager->ban($clientIp, $duration, "penetration:{$categories[0]}");

                return $this->createErrorResponse(403, 'IP has been banned');
            }
        }

        return $this->createErrorResponse(400, 'Suspicious activity detected');
    }

    /**
     * Every request surface scanned with the context of the value actually
     * being scanned, so the per-context gates in SusPatterns::buildRegexThreat
     * apply. The request body is routed through the form/multipart/JSON
     * extraction (port of guard_core/_utils/body_form_scan.py and
     * body_json_scan.py): urlencoded bodies scan as field name/value pairs
     * with the request_body:form_field context, multipart bodies as part
     * entries with the request_body:multipart_field context (binary-dense
     * file payloads reduced to binary islands via
     * detection_binary_min_run_length), JSON-content-type bodies as ordered
     * JSON walks (mongo-operator keys reported straight from the walk, keys
     * as plain request_body components, leaves as request_body values,
     * depth-capped subtrees as compact serializations), and everything else
     * as the one raw body. Query parameters and headers scan with their own
     * context; any of those values that itself parses as embedded JSON scans
     * leaf-first with the :embedded_json context suffix before the raw
     * value.
     *
     * Exclusion sets mirror the reference's config surface:
     * excluded_detection_params skips a query parameter's whole pair
     * (`key.lower() in excluded_params` in _scan_query_params), and
     * excluded_detection_body_fields skips urlencoded pairs and multipart
     * parts by field name and whole JSON subtrees by key at any nesting
     * depth. Query and header values thread the body-field exclusion into
     * their embedded-JSON walks like the reference's
     * _scan_query_param_value / _scan_normal_header_component.
     *
     * @return list<array{string, string, ?string}> [content, context, forcedCategory]
     */
    private function scanValues(GuardRequest $request): array
    {
        $values = [[$request->urlPath(), 'url_path', null]];
        $excludedParams = $this->config->excludedDetectionParams;
        $excludedBodyFields = $this->config->excludedDetectionBodyFields;
        foreach ($request->queryParams() as $name => $value) {
            if (isset($excludedParams[strtolower((string) $name)])) {
                continue;
            }
            foreach ((array) $value as $single) {
                foreach ($this->scannedValue((string) $single, 'query_param', $excludedBodyFields) as $entry) {
                    $values[] = $entry;
                }
            }
        }
        $headers = $request->headers();
        foreach ($headers->all() as $name => $value) {
            if (isset($this->config->logSensitiveHeaders[strtolower($name)])) {
                continue;
            }
            foreach ($this->scannedValue((string) $value, 'header', $excludedBodyFields) as $entry) {
                $values[] = $entry;
            }
        }
        $body = $request->body();
        if ($body !== '') {
            $contentType = $headers->get('content-type') ?? '';
            foreach (BodyFormScan::bodyScanEntries($body, $contentType, $this->config->detectionBinaryMinRunLength, $excludedBodyFields) as [$content, $context, $forcedCategory]) {
                $values[] = [$content, $context, $forcedCategory];
            }
        }

        return $values;
    }

    /**
     * One query or header value: an embedded JSON value walks leaf-first
     * with the context plus the :embedded_json suffix (the reference's
     * embedded-JSON check runs for every non-body context, with the
     * excluded body fields skipping whole JSON subtrees by key), then the
     * raw value scans with the plain context.
     *
     * @param array<string, true> $excludedBodyFields
     * @return list<array{string, string, null}>
     */
    private function scannedValue(string $value, string $context, array $excludedBodyFields = []): array
    {
        $root = JsonWalk::parse($value);
        if ($root === null) {
            return [[$value, $context, null]];
        }
        $entries = JsonWalk::walkEntries($root, $context . JsonWalk::EMBEDDED_JSON_LEAF_CONTEXT_SUFFIX, $excludedBodyFields);
        $entries[] = [$value, $context, null];

        return $entries;
    }

    private function incrementCount(string $ip): int
    {
        $count = ($this->suspiciousCounts[$ip] ?? 0) + 1;
        unset($this->suspiciousCounts[$ip]);
        $this->suspiciousCounts[$ip] = $count;
        while (count($this->suspiciousCounts) > self::MAX_TRACKED_IPS) {
            $oldest = array_key_first($this->suspiciousCounts);
            unset($this->suspiciousCounts[$oldest]);
        }

        return $count;
    }
}
