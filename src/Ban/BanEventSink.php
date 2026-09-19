<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Ban;

interface BanEventSink
{
    public function sendBanEvent(string $ip, int $duration, string $reason): void;

    public function sendUnbanEvent(string $ip): void;
}
