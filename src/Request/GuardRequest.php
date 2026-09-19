<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Request;

interface GuardRequest
{
    public function urlPath(): string;

    public function urlScheme(): string;

    public function urlFull(): string;

    public function urlReplaceScheme(string $scheme): string;

    public function method(): string;

    public function clientHost(): ?string;

    public function headers(): HeaderBag;

    /** @return array<string, string|list<string>> */
    public function queryParams(): array;

    public function body(): string;

    public function state(): RequestState;
}
