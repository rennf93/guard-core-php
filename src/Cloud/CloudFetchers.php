<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Cloud;

use RenzoFranceschini\GuardCore\Ip\CanonicalIp;

final class CloudFetchers
{
    public const AZURE_DOWNLOAD_MAX_ATTEMPTS = 3;
    public const AZURE_DOWNLOAD_RETRY_DELAY_SECONDS = 2.0;
    public const AZURE_DOWNLOAD_MAX_ELAPSED_SECONDS = 20.0;
    public const AZURE_DOWNLOAD_ATTEMPT_TIMEOUT_SECONDS = 10.0;
    public const AZURE_PAGE_FETCH_TIMEOUT_SECONDS = 10.0;
    public const AZURE_TRUSTED_DOWNLOAD_HOST = 'download.microsoft.com';
    public const AZURE_SERVICE_TAGS_STALE_WARNING_DAYS = 90;
    public const AZURE_CLOUD_SERVICE_TAG_NAME = 'AzureCloud';

    /** @return array<string, bool> */
    public static function fetchProviderRanges(string $provider, HttpClient $client): array
    {
        $fetchers = [
            'AWS' => static fn (): array => self::fetchAwsIpRanges($client),
            'GCP' => static fn (): array => self::fetchGcpIpRanges($client),
            'Azure' => static fn (): array => self::fetchAzureIpRanges($client),
            'DigitalOcean' => static fn (): array => self::fetchDigitalOceanIpRanges($client),
            'Linode' => static fn (): array => self::fetchLinodeIpRanges($client),
            'Vultr' => static fn (): array => self::fetchVultrIpRanges($client),
        ];
        $fetcher = $fetchers[$provider] ?? null;
        if ($fetcher === null) {
            return [];
        }

        return $fetcher();
    }

    /** @return array{0: array<string, bool>, 1: array<string, string>} */
    public static function fetchAwsIpRanges(HttpClient $client): array
    {
        try {
            $response = $client->get('https://ip-ranges.amazonaws.com/ip-ranges.json', ['timeout' => 10.0]);
            $response->isSuccess() || throw new CloudHttpException('AWS HTTP status ' . $response->status);
            $data = self::decodeJson($response->body);
            $networks = [];
            $regions = [];
            foreach ($data['prefixes'] ?? [] as $range) {
                if (!is_array($range) || ($range['service'] ?? null) !== 'AMAZON') {
                    continue;
                }
                $prefix = $range['ip_prefix'] ?? null;
                if (!is_string($prefix)) {
                    continue;
                }
                $network = CanonicalIp::canonicalNetwork($prefix);
                $networks[$network] = true;
                $region = $range['region'] ?? null;
                if (is_string($region) && $region !== '') {
                    $regions[$network] = $region;
                }
            }

            return [$networks, $regions];
        } catch (\Throwable $e) {
            self::log('Failed to fetch AWS IP ranges: ' . $e->getMessage());

            return [[], []];
        }
    }

    /** @return array{0: array<string, bool>, 1: array<string, string>} */
    public static function fetchGcpIpRanges(HttpClient $client): array
    {
        try {
            $response = $client->get('https://www.gstatic.com/ipranges/cloud.json', ['timeout' => 10.0]);
            $response->isSuccess() || throw new CloudHttpException('GCP HTTP status ' . $response->status);
            $data = self::decodeJson($response->body);
            $networks = [];
            $regions = [];
            foreach ($data['prefixes'] ?? [] as $range) {
                if (!is_array($range)) {
                    continue;
                }
                $prefix = $range['ipv4Prefix'] ?? $range['ipv6Prefix'] ?? null;
                if (!is_string($prefix) || $prefix === '') {
                    continue;
                }
                $network = CanonicalIp::canonicalNetwork($prefix);
                $networks[$network] = true;
                $scope = $range['scope'] ?? null;
                if (is_string($scope) && $scope !== '') {
                    $regions[$network] = $scope;
                }
            }

            return [$networks, $regions];
        } catch (\Throwable $e) {
            self::log('Failed to fetch GCP IP ranges: ' . $e->getMessage());

            return [[], []];
        }
    }

    /** @return array{0: array<string, bool>, 1: array<string, string>} */
    public static function fetchAzureIpRanges(HttpClient $client): array
    {
        try {
            $deadline = microtime(true) + self::AZURE_DOWNLOAD_MAX_ELAPSED_SECONDS;
            $pageTimeout = min(self::AZURE_PAGE_FETCH_TIMEOUT_SECONDS, $deadline - microtime(true));
            if ($pageTimeout <= 0) {
                throw new CloudHttpException('Azure IP ranges download exceeded max elapsed time');
            }
            $page = $client->get('https://www.microsoft.com/en-us/download/details.aspx?id=56519', [
                'timeout' => $pageTimeout,
                'headers' => [
                    'User-Agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                        . 'AppleWebKit/537.36 (KHTML, like Gecko) '
                        . 'Chrome/91.0.4472.124 Safari/537.36',
                ],
            ]);
            $page->isSuccess() || throw new CloudHttpException('Azure page HTTP status ' . $page->status);

            $downloadUrl = self::extractAzureDownloadUrl(html_entity_decode($page->body));
            if ($downloadUrl === null) {
                throw new CloudHttpException('Could not find Azure IP ranges download URL');
            }
            self::warnIfServiceTagsUrlIsStale($downloadUrl);

            $data = self::downloadAzureServiceTags($client, $downloadUrl, $deadline);
            $networks = [];
            foreach (self::selectAzureCloudPrefixes($data) as $prefix) {
                $networks[CanonicalIp::canonicalNetwork($prefix)] = true;
            }

            return [$networks, []];
        } catch (\Throwable $e) {
            self::log('Failed to fetch Azure IP ranges: ' . $e->getMessage());

            return [[], []];
        }
    }

    /** @return array<string, mixed> */
    public static function downloadAzureServiceTags(HttpClient $client, string $downloadUrl, ?float $deadline = null): array
    {
        $deadline = $deadline ?? microtime(true) + self::AZURE_DOWNLOAD_MAX_ELAPSED_SECONDS;
        $attempt = 0;
        while (true) {
            $remaining = $deadline - microtime(true);
            if ($remaining <= 0) {
                throw new CloudHttpException('Azure IP ranges download exceeded max elapsed time');
            }
            $attempt++;
            $attemptTimeout = min(self::AZURE_DOWNLOAD_ATTEMPT_TIMEOUT_SECONDS, $remaining);
            try {
                $response = $client->get($downloadUrl, [
                    'timeout' => $attemptTimeout,
                    'allowRedirects' => false,
                ]);
            } catch (CloudHttpException $e) {
                $remaining = $deadline - microtime(true);
                if ($attempt >= self::AZURE_DOWNLOAD_MAX_ATTEMPTS || $remaining <= 0) {
                    throw $e;
                }
                usleep((int) (min(self::AZURE_DOWNLOAD_RETRY_DELAY_SECONDS, $remaining) * 1000000));
                continue;
            }
            if ($response->status >= 300 && $response->status < 400) {
                throw new CloudHttpException(
                    'Azure IP ranges download redirected (status ' . $response->status . '); refusing to follow redirects'
                );
            }
            $response->isSuccess() || throw new CloudHttpException('Azure ServiceTags HTTP status ' . $response->status);

            return self::decodeJson($response->body);
        }
    }

    public static function isTrustedAzureDownloadUrl(string $url): bool
    {
        $host = parse_url($url, PHP_URL_HOST);

        return parse_url($url, PHP_URL_SCHEME) === 'https' && $host === self::AZURE_TRUSTED_DOWNLOAD_HOST;
    }

    public static function parseServiceTagsDate(string $url): ?\DateTimeImmutable
    {
        if (preg_match('/ServiceTags_Public_(\d{8})/', $url, $m) !== 1) {
            return null;
        }
        $date = \DateTimeImmutable::createFromFormat('Ymd', $m[1], new \DateTimeZone('UTC'));
        if ($date === false || $date->format('Ymd') !== $m[1]) {
            return null;
        }
        if ($date > new \DateTimeImmutable('now', new \DateTimeZone('UTC'))) {
            return null;
        }

        return $date;
    }

    /** @param list<string> $candidates */
    public static function serviceTagsSortKey(string $url): array
    {
        $date = self::parseServiceTagsDate($url);

        return [$date !== null, $date ?? new \DateTimeImmutable('@0'), $url];
    }

    public static function warnIfServiceTagsUrlIsStale(string $url): void
    {
        $date = self::parseServiceTagsDate($url);
        if ($date === null) {
            self::log('Selected Azure ServiceTags URL has no parseable date, cannot confirm it is current: ' . $url);

            return;
        }
        $ageDays = (int) ((new \DateTimeImmutable('now', new \DateTimeZone('UTC'))->getTimestamp() - $date->getTimestamp()) / 86400);
        if ($ageDays > self::AZURE_SERVICE_TAGS_STALE_WARNING_DAYS) {
            self::log('Selected Azure ServiceTags URL is ' . $ageDays . ' days old, possibly stale: ' . $url);
        }
    }

    public static function extractFailoverLinkUrl(string $decodedHtml): ?string
    {
        if (preg_match('/<a\b[^>]*\bid=["\']failoverLink["\'][^>]*>/', $decodedHtml, $anchor) !== 1) {
            return null;
        }
        if (preg_match('/href=["\']([^"\']+)["\']/', $anchor[0], $href) !== 1) {
            return null;
        }

        return self::isTrustedAzureDownloadUrl($href[1]) ? $href[1] : null;
    }

    /**
     * @return list<string>
     */
    public static function extractNewestServiceTagsUrlCandidates(string $decodedHtml): array
    {
        if (preg_match_all('/https:\/\/download\.microsoft\.com\/[^"\'\s<>]+ServiceTags[^"\'\s<>]*\.json(?:\?[^"\'\s<>]*)?/', $decodedHtml, $m) !== 1) {
            return [];
        }
        $candidates = [];
        foreach ($m[0] as $url) {
            if (self::isTrustedAzureDownloadUrl($url)) {
                $candidates[] = $url;
            }
        }

        return $candidates;
    }

    public static function extractNewestServiceTagsUrl(string $decodedHtml): ?string
    {
        $candidates = self::extractNewestServiceTagsUrlCandidates($decodedHtml);
        if ($candidates === []) {
            return null;
        }
        usort($candidates, static fn (string $a, string $b): int => self::serviceTagsSortKey($a) <=> self::serviceTagsSortKey($b));

        return $candidates[count($candidates) - 1];
    }

    public static function extractGenericJsonUrl(string $decodedHtml): ?string
    {
        if (preg_match('/href=["\'](https:\/\/download\.microsoft\.com\/[^"\']+\.json(?:\?[^"\']*)?)["\']/', $decodedHtml, $m) !== 1) {
            return null;
        }

        return self::isTrustedAzureDownloadUrl($m[1]) ? $m[1] : null;
    }

    public static function extractAzureDownloadUrl(string $decodedHtml): ?string
    {
        return self::extractFailoverLinkUrl($decodedHtml)
            ?? self::extractNewestServiceTagsUrl($decodedHtml)
            ?? self::extractGenericJsonUrl($decodedHtml);
    }

    /** @return list<string> */
    public static function selectAzureCloudPrefixes(array $data): array
    {
        foreach ($data['values'] ?? [] as $entry) {
            if (is_array($entry) && ($entry['name'] ?? null) === self::AZURE_CLOUD_SERVICE_TAG_NAME) {
                $prefixes = $entry['properties']['addressPrefixes'] ?? [];
                return array_values(array_filter($prefixes, is_string(...)));
            }
        }
        self::log("Azure ServiceTags document has no '" . self::AZURE_CLOUD_SERVICE_TAG_NAME . "' tag");

        return [];
    }

    public static function fetchCsvPrefixNetworks(HttpClient $client, string $url): array
    {
        $response = $client->get($url, ['timeout' => 10.0]);
        $response->isSuccess() || throw new CloudHttpException('CSV fetch HTTP status ' . $response->status);

        return self::parseCsvPrefixes($response->body);
    }

    /** @return array<string, bool> */
    public static function parseCsvPrefixes(string $body): array
    {
        $networks = [];
        foreach (preg_split('/\r\n|\r|\n/', $body) ?: [] as $rawLine) {
            $line = trim($rawLine);
            if ($line === '' || str_starts_with($line, '#')) {
                continue;
            }
            $prefix = trim(explode(',', $line, 2)[0]);
            if ($prefix === '') {
                continue;
            }
            try {
                $networks[CanonicalIp::canonicalNetwork($prefix)] = true;
            } catch (\InvalidArgumentException) {
                continue;
            }
        }

        return $networks;
    }

    /** @return array{0: array<string, bool>, 1: array<string, string>} */
    public static function fetchDigitalOceanIpRanges(HttpClient $client): array
    {
        try {
            return [self::fetchCsvPrefixNetworks($client, 'https://www.digitalocean.com/geo/google.csv'), []];
        } catch (\Throwable $e) {
            self::log('Failed to fetch DigitalOcean IP ranges: ' . $e->getMessage());

            return [[], []];
        }
    }

    /** @return array{0: array<string, bool>, 1: array<string, string>} */
    public static function fetchLinodeIpRanges(HttpClient $client): array
    {
        try {
            return [self::fetchCsvPrefixNetworks($client, 'https://geoip.linode.com/'), []];
        } catch (\Throwable $e) {
            self::log('Failed to fetch Linode IP ranges: ' . $e->getMessage());

            return [[], []];
        }
    }

    /** @return array{0: array<string, bool>, 1: array<string, string>} */
    public static function fetchVultrIpRanges(HttpClient $client): array
    {
        try {
            $response = $client->get('https://geofeed.constant.com/?json', ['timeout' => 10.0]);
            $response->isSuccess() || throw new CloudHttpException('Vultr HTTP status ' . $response->status);
            $data = self::decodeJson($response->body);
            $networks = [];
            foreach ($data['subnets'] ?? [] as $entry) {
                if (!is_array($entry)) {
                    continue;
                }
                $prefix = $entry['ip_prefix'] ?? null;
                if (!is_string($prefix) || $prefix === '') {
                    continue;
                }
                try {
                    $networks[CanonicalIp::canonicalNetwork($prefix)] = true;
                } catch (\InvalidArgumentException) {
                    continue;
                }
            }

            return [$networks, []];
        } catch (\Throwable $e) {
            self::log('Failed to fetch Vultr IP ranges: ' . $e->getMessage());

            return [[], []];
        }
    }

    /** @return array<string, mixed> */
    private static function decodeJson(string $body): array
    {
        $decoded = json_decode($body, true);
        if (!is_array($decoded)) {
            throw new CloudHttpException('invalid JSON payload');
        }

        return $decoded;
    }

    private static function log(string $message): void
    {
        error_log('[guard_core] ' . $message);
    }
}
