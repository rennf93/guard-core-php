<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Cloud;

interface HttpClient
{
    /**
     * @param array{timeout?: float, headers?: array<string, string>, allowRedirects?: bool} $options
     * @throws CloudHttpException on transport failure
     */
    public function get(string $url, array $options = []): HttpResponse;
}

final class CloudHttpException extends \RuntimeException
{
}

final class HttpResponse
{
    public function __construct(
        public readonly int $status,
        public readonly string $body
    ) {
    }

    public function isSuccess(): bool
    {
        return $this->status >= 200 && $this->status < 300;
    }
}
