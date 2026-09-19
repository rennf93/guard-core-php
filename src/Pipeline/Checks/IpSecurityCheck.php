<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Pipeline\Checks;

use RenzoFranceschini\GuardCore\Ban\IpBanManager;
use RenzoFranceschini\GuardCore\Config\SecurityConfig;
use RenzoFranceschini\GuardCore\Ip\CanonicalIp;
use RenzoFranceschini\GuardCore\Pipeline\SecurityCheck;
use RenzoFranceschini\GuardCore\Request\GuardRequest;
use RenzoFranceschini\GuardCore\Request\GuardResponse;
use RenzoFranceschini\GuardCore\Request\GuardResponseFactory;
use RenzoFranceschini\GuardCore\Routing\RouteResolver;

final class IpSecurityCheck extends SecurityCheck
{
    public function __construct(
        SecurityConfig $config,
        GuardResponseFactory $responseFactory,
        private readonly ?IpBanManager $ipBanManager,
        private readonly RouteResolver $routeResolver
    ) {
        parent::__construct($config, $responseFactory);
    }

    public function checkName(): string
    {
        return 'ip_security';
    }

    public function enforcedOnExcludedPaths(): bool
    {
        return true;
    }

    public function check(GuardRequest $request): ?GuardResponse
    {
        $clientIp = $request->state()->clientIp;
        if ($clientIp === null) {
            return null;
        }

        $routeConfig = $request->state()->routeConfig;

        if (!$this->routeResolver->shouldBypassCheck('ip_ban', $routeConfig)
            && $this->ipBanManager !== null
            && $this->ipBanManager->isIpBanned($clientIp)
        ) {
            $this->stashBlock($request, "Banned IP attempted access: {$clientIp}", 'banned');
            if (!$this->isPassiveMode()) {
                return $this->createErrorResponse(403, 'IP address banned');
            }

            return null;
        }

        if ($this->routeResolver->shouldBypassCheck('ip', $routeConfig)) {
            return null;
        }

        $whitelist = $this->config->whitelist;
        $whitelistActive = $whitelist !== null && $whitelist !== [];
        $request->state()->isWhitelisted = false;

        foreach ($this->config->blacklist as $entry) {
            if (self::matches($entry, $clientIp)) {
                $this->stashBlock($request, "IP blacklisted: {$clientIp}", 'global');
                if (!$this->isPassiveMode()) {
                    return $this->createErrorResponse(403, 'Forbidden');
                }

                return null;
            }
        }

        if ($whitelistActive) {
            $allowed = false;
            foreach ($whitelist as $entry) {
                if (self::matches($entry, $clientIp)) {
                    $allowed = true;
                    break;
                }
            }
            if (!$allowed) {
                $this->stashBlock($request, "IP not in whitelist: {$clientIp}", 'global');
                if (!$this->isPassiveMode()) {
                    return $this->createErrorResponse(403, 'Forbidden');
                }

                return null;
            }
            $request->state()->isWhitelisted = true;
        }

        return null;
    }

    private static function matches(string $entry, string $ip): bool
    {
        if (str_contains($entry, '/')) {
            $addr = CanonicalIp::parse($ip);

            return $addr !== null && CanonicalIp::networkContains($entry, $addr);
        }

        return CanonicalIp::parse($ip) === $entry;
    }
}
