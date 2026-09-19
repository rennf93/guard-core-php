<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Cloud;

use RenzoFranceschini\GuardCore\Ip\CanonicalIp;

final class CloudProviderRegistry
{
    public const PROVIDERS = ['AWS', 'GCP', 'Azure', 'DigitalOcean', 'Linode', 'Vultr'];

    /**
     * Spec 10 Selectors: each selector splits at the first ':!'. The bare
     * provider is always blocked; a non-empty region after ':!' registers a
     * carve-out. A trailing bare '!' (empty region) is a plain block.
     *
     * @param list<string> $selectors
     * @return array{0: list<string>, 1: array<string, list<string>>}
     */
    public static function parseCloudSelectors(array $selectors): array
    {
        $blocked = [];
        $carveouts = [];
        foreach ($selectors as $selector) {
            $marker = strpos($selector, ':!');
            if ($marker === false) {
                $provider = $selector;
                $region = '';
            } else {
                $provider = substr($selector, 0, $marker);
                $region = substr($selector, $marker + 2);
            }
            if (!in_array($provider, $blocked, true)) {
                $blocked[] = $provider;
            }
            if ($marker !== false && $region !== '') {
                $carveouts[$provider][] = $region;
            }
        }

        return [$blocked, $carveouts];
    }

    /**
     * @param list<string> $providers
     * @return list<string>
     */
    public static function bareProviderNames(array $providers): array
    {
        $names = [];
        foreach ($providers as $provider) {
            $marker = strpos($provider, ':!');
            $bare = $marker === false ? $provider : substr($provider, 0, $marker);
            if (!in_array($bare, $names, true)) {
                $names[] = $bare;
            }
        }

        return $names;
    }

    /**
     * Spec 08 cloud_ranges_v2 entry grammar: "<network>" or
     * "<network>|<region>".
     *
     * @param array<string, bool> $networks canonical network strings
     * @param array<string, string> $regions network string => region
     * @return list<string>
     */
    public static function encodeCached(array $networks, array $regions): array
    {
        $encoded = [];
        foreach (array_keys($networks) as $network) {
            $region = $regions[$network] ?? null;
            $encoded[] = $region !== null && $region !== '' ? $network . '|' . $region : $network;
        }

        return $encoded;
    }

    /**
     * An unparseable prefix throws: a corrupt cache entry is an error, not
     * a skip.
     *
     * @param list<string> $entries
     * @return array{0: array<string, bool>, 1: array<string, string>}
     */
    public static function decodeCached(array $entries): array
    {
        $networks = [];
        $regions = [];
        foreach ($entries as $entry) {
            $sep = strpos($entry, '|');
            if ($sep === false) {
                $prefix = $entry;
                $region = '';
            } else {
                $prefix = substr($entry, 0, $sep);
                $region = substr($entry, $sep + 1);
            }
            $network = CanonicalIp::canonicalNetwork($prefix);
            $networks[$network] = true;
            if ($sep !== false && $region !== '') {
                $regions[$network] = $region;
            }
        }

        return [$networks, $regions];
    }
}
