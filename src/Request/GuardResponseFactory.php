<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Request;

final class GuardResponseFactory
{
    public function __construct(private readonly ?\Closure $responseModifier = null)
    {
    }

    public function createResponse(?string $content = null, int $statusCode = 200): GuardResponse
    {
        return new GuardResponse($statusCode, new HeaderBag(), $content);
    }

    public function createRedirectResponse(string $url, int $statusCode = 307): GuardResponse
    {
        $headers = new HeaderBag();
        $headers->set('Location', $url);

        return new GuardResponse($statusCode, $headers, null);
    }

    public function applyModifier(mixed $response): mixed
    {
        if ($this->responseModifier === null) {
            return $response;
        }
        try {
            return ($this->responseModifier)($response);
        } catch (\Throwable) {
            return $response;
        }
    }
}
