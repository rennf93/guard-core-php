<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Request;

use RenzoFranceschini\GuardCore\Config\SecurityConfig;
use RenzoFranceschini\GuardCore\Ip\CanonicalIp;

final class ClientIpResolver
{
    public const UNKNOWN_CLIENT_IDENTITY = 'unknown';

    public static function extract(GuardRequest $request, SecurityConfig $config): string
    {
        $cached = $request->state()->clientIp;
        if ($cached !== null && $cached !== '') {
            return $cached;
        }

        $connectingIp = $request->clientHost();
        if ($connectingIp === null) {
            return in_array('unix', $config->trustedProxies, true)
                ? self::resolveForwardedChain(
                    self::UNKNOWN_CLIENT_IDENTITY,
                    $request->headers()->get('x-forwarded-for'),
                    $config->trustedProxyDepth,
                    $config->trustedProxies
                )
                : self::UNKNOWN_CLIENT_IDENTITY;
        }

        $canonical = CanonicalIp::parse($connectingIp) ?? $connectingIp;
        $forwardedFor = $request->headers()->get('x-forwarded-for');

        if ($config->trustedProxies === []) {
            return $canonical;
        }

        if (!self::isTrustedProxy($connectingIp, $config->trustedProxies)) {
            return $canonical;
        }

        return self::resolveForwardedChain(
            $canonical,
            $forwardedFor,
            $config->trustedProxyDepth,
            $config->trustedProxies
        );
    }

    /** @param list<string> $trustedProxies */
    public static function isTrustedProxy(string $connectingIp, array $trustedProxies): bool
    {
        $parsed = CanonicalIp::parse($connectingIp);
        foreach ($trustedProxies as $proxy) {
            if (!str_contains($proxy, '/')) {
                if ($connectingIp === $proxy) {
                    return true;
                }
                continue;
            }
            if ($parsed !== null && CanonicalIp::networkContains($proxy, $parsed)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param list<string> $trustedProxies
     */
    public static function resolveForwardedChain(
        string $connectingIp,
        ?string $forwardedFor,
        int $proxyDepth,
        array $trustedProxies
    ): string {
        if ($forwardedFor === null || $forwardedFor === '') {
            return $connectingIp;
        }

        $ips = array_map('trim', explode(',', $forwardedFor));
        $ips = array_values(array_filter($ips, static fn (string $ip): bool => $ip !== ''));
        if ($ips === []) {
            return $connectingIp;
        }

        if (count($ips) < $proxyDepth) {
            return $connectingIp;
        }

        $candidate = $ips[count($ips) - $proxyDepth];
        $parsed = CanonicalIp::parse($candidate);

        return $parsed ?? $connectingIp;
    }
}
