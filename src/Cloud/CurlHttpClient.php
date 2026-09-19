<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Cloud;

final class CurlHttpClient implements HttpClient
{
    public function get(string $url, array $options = []): HttpResponse
    {
        $timeout = $options['timeout'] ?? 10.0;
        $headers = $options['headers'] ?? [];
        $allowRedirects = $options['allowRedirects'] ?? true;

        $rawHeaders = [];
        foreach ($headers as $name => $value) {
            $rawHeaders[] = $name . ': ' . $value;
        }

        $handle = curl_init($url);
        if ($handle === false) {
            throw new CloudHttpException('curl_init failed for ' . $url);
        }
        curl_setopt_array($handle, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => $allowRedirects,
            CURLOPT_MAXREDIRS => $allowRedirects ? 5 : 0,
            CURLOPT_TIMEOUT_MS => (int) round($timeout * 1000),
            CURLOPT_CONNECTTIMEOUT_MS => (int) round(min($timeout, 5.0) * 1000),
            CURLOPT_HTTPHEADER => $rawHeaders,
            CURLOPT_USERAGENT => 'guard-core',
        ]);
        $body = curl_exec($handle);
        if ($body === false) {
            $error = curl_error($handle);
            curl_close($handle);
            throw new CloudHttpException($error !== '' ? $error : 'curl request failed');
        }
        $status = (int) curl_getinfo($handle, CURLINFO_RESPONSE_CODE);
        curl_close($handle);

        return new HttpResponse($status, (string) $body);
    }
}
