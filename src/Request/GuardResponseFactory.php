<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Request;

final class GuardResponseFactory
{
    public function __construct(private readonly ?\Closure $responseModifier = null)
    {
    }

    /**
     * Body responses declare text/plain so block/error responses copied
     * verbatim by the adapters never go out with no Content-Type while the
     * security headers carry X-Content-Type-Options: nosniff (parity with
     * fastapi-guard #144, upstream commit 4059fbe). Redirects carry no body
     * and stay header-minimal.
     */
    public function createResponse(?string $content = null, int $statusCode = 200): GuardResponse
    {
        $headers = new HeaderBag();
        if ($content !== null && $content !== '') {
            $headers->set('Content-Type', 'text/plain; charset=utf-8');
        }

        return new GuardResponse($statusCode, $headers, $content);
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
