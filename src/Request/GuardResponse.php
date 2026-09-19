<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Request;

final class GuardResponse
{
    public function __construct(
        private int $statusCode,
        private HeaderBag $headers = new HeaderBag(),
        private ?string $body = null
    ) {
    }

    public function statusCode(): int
    {
        return $this->statusCode;
    }

    public function headers(): HeaderBag
    {
        return $this->headers;
    }

    public function body(): ?string
    {
        return $this->body;
    }
}
