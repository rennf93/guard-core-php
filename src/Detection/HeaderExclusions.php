<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Detection;

/**
 * Excluded-header semantics for the penetration scan, ported from
 * guard_core/_utils/detection_config.py.
 *
 * The hardcoded proxy identity set (`_DEFAULT_EXCLUDED_HEADERS`) merges with
 * the configured `excluded_detection_headers` entries, and an excluded header
 * does not leave the scan: like the reference's `_scan_excluded_header_component`,
 * it scans with every enabled category except the ones its value is known to
 * false-positive (`_excluded_header_skip_categories`). The skip is `ssrf`
 * only, and only when the header is address-carrying
 * (`_HEADER_CATEGORY_EXCLUSIONS`) or its whole value parses as an address
 * chain (`_value_looks_like_address_chain` over
 * `_strip_forwarded_entry_port` tokens), so an attack payload in the same
 * header still detects.
 */
final class HeaderExclusions
{
    /**
     * Lowercase header names the reference excludes by default: proxy
     * identity, forwarding and browser-fingerprint headers.
     *
     * @var list<string>
     */
    public const DEFAULT_EXCLUDED_HEADERS = [
        'host',
        'user-agent',
        'accept',
        'accept-encoding',
        'connection',
        'origin',
        'referer',
        'sec-fetch-site',
        'sec-fetch-mode',
        'sec-fetch-dest',
        'sec-ch-ua',
        'sec-ch-ua-mobile',
        'sec-ch-ua-platform',
        'forwarded',
        'x-forwarded-for',
        'x-forwarded-host',
        'x-forwarded-proto',
        'x-real-ip',
        'x-client-ip',
        'x-cluster-client-ip',
        'cf-connecting-ip',
        'true-client-ip',
        'fly-client-ip',
        'x-envoy-external-address',
    ];

    /**
     * Excluded headers whose typical values are client addresses; the ssrf
     * category skips for any value, not just address chains.
     *
     * @var array<string, true>
     */
    private const ADDRESS_HEADER_SKIP_CATEGORIES = [
        'host' => true,
        'origin' => true,
        'x-forwarded-for' => true,
        'x-forwarded-host' => true,
        'x-real-ip' => true,
        'x-client-ip' => true,
        'x-cluster-client-ip' => true,
        'cf-connecting-ip' => true,
        'true-client-ip' => true,
        'fly-client-ip' => true,
        'x-envoy-external-address' => true,
        'via' => true,
    ];

    /**
     * The exclusion set the header scan routes through: the hardcoded default
     * set merged with the config entries (the reference's
     * `_resolve_excluded_headers`; entries are keyed lowercase, config values
     * stay verbatim like every other exclusion field).
     *
     * @param array<string, true> $configured
     * @return array<string, true>
     */
    public static function mergedExcludedNames(array $configured): array
    {
        $merged = [];
        foreach (self::DEFAULT_EXCLUDED_HEADERS as $name) {
            $merged[$name] = true;
        }
        foreach (array_keys($configured) as $name) {
            $merged[strtolower((string) $name)] = true;
        }

        return $merged;
    }

    /**
     * Categories the scan must suppress for one excluded header value. A
     * non-empty result never contains more than `ssrf`; an empty result means
     * the header scans with every enabled category.
     *
     * @return array<string, true>
     */
    public static function skipCategories(string $name, string $value): array
    {
        $normalized = strtolower(trim($name));
        if (isset(self::ADDRESS_HEADER_SKIP_CATEGORIES[$normalized])) {
            return ['ssrf' => true];
        }
        if (self::valueLooksLikeAddressChain($value)) {
            return ['ssrf' => true];
        }

        return [];
    }

    /**
     * Port of guard_core._utils.ip_extraction._strip_forwarded_entry_port:
     * remove the port from a Forwarded/X-Forwarded-For list entry so the
     * address itself can be parsed ("1.2.3.4:8080" -> "1.2.3.4",
     * "[::1]:8080" -> "::1").
     */
    public static function stripForwardedEntryPort(string $value): string
    {
        if (str_starts_with($value, '[')) {
            $closing = strpos($value, ']');
            if ($closing === false) {
                return $value;
            }
            $remainder = substr($value, $closing + 1);
            if ($remainder !== '' && !preg_match('/^:\d+$/', $remainder)) {
                return $value;
            }

            return substr($value, 1, $closing - 1);
        }
        if (substr_count($value, ':') === 1) {
            [$host, $port] = explode(':', $value, 2);
            if (ctype_digit($port)) {
                return $host;
            }
        }

        return $value;
    }

    /**
     * Port of `_value_looks_like_address_chain`: every comma-separated token
     * parses as an IP address once its port entry is stripped, so a value
     * like "10.0.0.5, 172.16.0.1" reads as a proxy chain and not as an
     * attack payload.
     */
    public static function valueLooksLikeAddressChain(string $value): bool
    {
        $tokens = [];
        foreach (explode(',', $value) as $token) {
            $token = trim($token);
            if ($token !== '') {
                $tokens[] = $token;
            }
        }
        if ($tokens === []) {
            return false;
        }
        foreach ($tokens as $token) {
            if (filter_var(self::stripForwardedEntryPort($token), FILTER_VALIDATE_IP) === false) {
                return false;
            }
        }

        return true;
    }
}
