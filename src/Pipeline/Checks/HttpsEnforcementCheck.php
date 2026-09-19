<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Pipeline\Checks;

use RenzoFranceschini\GuardCore\Config\SecurityConfig;
use RenzoFranceschini\GuardCore\Pipeline\CheckFactory;
use RenzoFranceschini\GuardCore\Pipeline\SecurityCheck;
use RenzoFranceschini\GuardCore\Request\ClientIpResolver;
use RenzoFranceschini\GuardCore\Request\GuardRequest;
use RenzoFranceschini\GuardCore\Request\GuardResponse;
use RenzoFranceschini\GuardCore\Request\GuardResponseFactory;
use RenzoFranceschini\GuardCore\Routing\RouteConfig;

final class HttpsEnforcementCheck extends SecurityCheck
{
    public function __construct(
        SecurityConfig $config,
        GuardResponseFactory $responseFactory
    ) {
        parent::__construct($config, $responseFactory);
    }

    public function checkName(): string
    {
        return 'https_enforcement';
    }

    public function appliesTo(SecurityConfig $config, ?array $routeConfigs): bool
    {
        if ($config->enforceHttps) {
            return true;
        }

        return CheckFactory::routeConfigApplies($routeConfigs, fn (RouteConfig $rc): bool => $rc->requireHttps);
    }

    public function check(GuardRequest $request): ?GuardResponse
    {
        $routeConfig = $request->state()->routeConfig;
        $httpsRequired = $routeConfig !== null ? $routeConfig->requireHttps : $this->config->enforceHttps;
        if (!$httpsRequired) {
            return null;
        }

        if ($this->isRequestHttps($request)) {
            return null;
        }

        if (!$this->isPassiveMode()) {
            return $this->responseFactory->createRedirectResponse(
                $request->urlReplaceScheme('https'),
                301
            );
        }

        return null;
    }

    private function isRequestHttps(GuardRequest $request): bool
    {
        $isHttps = $request->urlScheme() === 'https';
        if ($isHttps) {
            return true;
        }

        $connectingIp = $request->clientHost();
        if (!$this->config->trustXForwardedProto
            || $this->config->trustedProxies === []
            || $connectingIp === null
        ) {
            return false;
        }

        if (!ClientIpResolver::isTrustedProxy($connectingIp, $this->config->trustedProxies)) {
            return false;
        }

        $forwardedProto = $request->headers()->get('x-forwarded-proto');

        return $forwardedProto !== null && strtolower($forwardedProto) === 'https';
    }
}
