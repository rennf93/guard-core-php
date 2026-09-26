<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Pipeline\Checks;

use RenzoFranceschini\GuardCore\Ban\IpBanManager;
use RenzoFranceschini\GuardCore\Config\SecurityConfig;
use RenzoFranceschini\GuardCore\Detection\BodyFormScan;
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
        foreach ($this->scanValues($request) as [$content, $context]) {
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
     * The request body is routed through the form/multipart extraction (port
     * of guard_core/_utils/body_form_scan.py): urlencoded bodies scan as
     * field name/value pairs with the request_body:form_field context,
     * multipart bodies as part entries with the request_body:multipart_field
     * context (binary-dense file payloads reduced to binary islands via
     * detection_binary_min_run_length), and everything else as the one raw
     * body. Values that parse as embedded JSON scan leaf-first with the
     * :embedded_json context suffix, so the per-context gates in
     * SusPatterns::buildRegexThreat see the context of the value actually
     * being scanned.
     *
     * @return list<array{string, string}>
     */
    private function scanValues(GuardRequest $request): array
    {
        $values = [[$request->urlPath(), 'url_path']];
        foreach ($request->queryParams() as $name => $value) {
            foreach ((array) $value as $single) {
                $values[] = [(string) $single, 'query_param'];
            }
        }
        $headers = $request->headers();
        foreach ($headers->all() as $name => $value) {
            if (isset($this->config->logSensitiveHeaders[strtolower($name)])) {
                continue;
            }
            $values[] = [(string) $value, 'header'];
        }
        $body = $request->body();
        if ($body !== '') {
            $contentType = $headers->get('content-type') ?? '';
            foreach (BodyFormScan::bodyScanEntries($body, $contentType, $this->config->detectionBinaryMinRunLength) as [$content, $context]) {
                $values[] = [$content, $context];
            }
        }

        return $values;
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
