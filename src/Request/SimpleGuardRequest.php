<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Request;

final class SimpleGuardRequest implements GuardRequest
{
    private string $body;

    private bool $bodyRead = false;

    private RequestState $state;

    /** @var \Closure(): string|null */
    private ?\Closure $bodyReader;

    /**
     * @param array<string, string> $headers
     * @param array<string, string|list<string>> $queryParams
     * @param (\Closure(): string)|null $bodyReader
     */
    public function __construct(
        private string $urlPath = '/',
        private string $urlScheme = 'http',
        private string $host = 'localhost',
        private string $method = 'GET',
        private ?string $clientHost = null,
        private array $headers = [],
        private array $queryParams = [],
        private string $rawQuery = '',
        string $body = '',
        ?\Closure $bodyReader = null,
        ?RequestState $state = null
    ) {
        $this->body = $body;
        $this->bodyRead = $bodyReader === null;
        $this->bodyReader = $bodyReader;
        $this->state = $state ?? new RequestState();
    }

    public function urlPath(): string
    {
        return $this->urlPath;
    }

    public function urlScheme(): string
    {
        return $this->urlScheme;
    }

    public function urlFull(): string
    {
        $url = $this->urlScheme . '://' . $this->host . $this->urlPath;
        $query = $this->rawQuery !== '' ? $this->rawQuery : http_build_query($this->queryParams);

        return $query !== '' ? $url . '?' . $query : $url;
    }

    public function urlReplaceScheme(string $scheme): string
    {
        $full = $this->urlFull();

        return $scheme . '://' . substr($full, strlen($this->urlScheme) + 3);
    }

    public function method(): string
    {
        return strtoupper($this->method);
    }

    public function clientHost(): ?string
    {
        return $this->clientHost;
    }

    public function headers(): HeaderBag
    {
        return new HeaderBag($this->headers);
    }

    public function queryParams(): array
    {
        return $this->queryParams;
    }

    public function body(): string
    {
        if (!$this->bodyRead) {
            $this->body = $this->bodyReader !== null ? ($this->bodyReader)() : '';
            $this->bodyRead = true;
        }

        return $this->body;
    }

    public function state(): RequestState
    {
        return $this->state;
    }
}
