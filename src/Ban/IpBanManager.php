<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Ban;

use RenzoFranceschini\GuardCore\Ip\CanonicalIp;
use RenzoFranceschini\GuardCore\Redis\GuardRedisException;
use RenzoFranceschini\GuardCore\Redis\RedisHandler;

final class IpBanManager
{
    public const LOCAL_CACHE_TTL_CAP_SECONDS = 3600;
    private const MAX_LOCAL_ENTRIES = 10000;
    private const BANNED_IPS_NAMESPACE = 'banned_ips';
    private const BANNED_NETWORKS_NAMESPACE = 'banned_networks';

    /** @var array<string, float> canonical ip => true expiry (epoch seconds) */
    private array $bannedIps = [];

    /** @var list<array{network: string, expiry: float}> */
    private array $bannedNetworks = [];

    private ?RedisHandler $redisHandler = null;

    /** @var list<string> */
    private array $trustedProxyNetworks;

    private ?\Closure $warn;

    private ?BanEventSink $events;

    /**
     * @param list<string> $trustedProxies IP or CIDR entries; invalid entries are skipped
     * @param (\Closure(string): void)|null $warn
     */
    public function __construct(
        array $trustedProxies = [],
        ?\Closure $warn = null,
        ?BanEventSink $events = null
    ) {
        $this->trustedProxyNetworks = array_values(array_filter(
            $trustedProxies,
            fn (string $entry): bool => self::isNetwork($entry)
        ));
        $this->warn = $warn;
        $this->events = $events;
    }

    public function initializeRedis(?RedisHandler $redisHandler): bool
    {
        $this->redisHandler = $redisHandler;

        return $this->migrateLegacyBanKeys();
    }

    public function ban(string $ip, int $duration, string $reason = 'threshold_exceeded'): bool
    {
        $ip = CanonicalIp::canonicalize($ip);
        if ($duration <= 0) {
            throw new \InvalidArgumentException("ban duration must be positive, got {$duration}");
        }
        $refusal = $this->selfDosRefusalReason($ip);
        if ($refusal !== null) {
            $space = $refusal === 'loopback'
                ? 'loopback'
                : 'a configured trusted proxy';
            $this->emitWarning("Refused to ban {$ip}: overlaps {$space} space and would self-DoS this deployment.");

            return false;
        }
        $target = self::parseNetwork($ip);
        if ($target !== null && self::isPrivateNetwork($target)) {
            $this->emitWarning("Banning private IP range {$ip}: if requests reach this service through a reverse proxy, this IP may be the proxy and the ban will block ALL users.");
        }
        if (str_contains($ip, '/')) {
            $this->banCidr($ip, $duration);
        } else {
            $this->banExactIp($ip, $duration, $reason);
        }

        return true;
    }

    public function isIpBanned(string $ip): bool
    {
        $ip = CanonicalIp::canonicalize($ip);
        $now = microtime(true);

        $expiry = $this->bannedIps[$ip] ?? null;
        if ($expiry !== null) {
            if ($now > $expiry) {
                unset($this->bannedIps[$ip]);

                return false;
            }

            return true;
        }

        $addr = CanonicalIp::parse($ip);
        if ($addr === null) {
            return false;
        }

        if ($this->checkNetworkCache($addr, $now)) {
            return true;
        }

        if ($this->redisHandler !== null) {
            return $this->checkRedisExact($ip, $now);
        }

        return false;
    }

    public function unban(string $ip): void
    {
        $ip = CanonicalIp::canonicalize($ip);
        unset($this->bannedIps[$ip]);

        if ($this->redisHandler !== null) {
            $this->redisHandler->delete(self::BANNED_IPS_NAMESPACE, $ip);
        }

        $this->events?->sendUnbanEvent($ip);
    }

    public function reset(): void
    {
        $this->bannedIps = [];
        $this->bannedNetworks = [];
        if ($this->redisHandler !== null) {
            $keys = $this->redisHandler->keys(self::BANNED_IPS_NAMESPACE . ':*');
            if ($keys !== []) {
                $this->redisHandler->connection()->del(...$keys);
            }
        }
    }

    private function banExactIp(string $ip, int $duration, string $reason): void
    {
        if (CanonicalIp::parse($ip) === null) {
            throw new \InvalidArgumentException("Invalid IP address '{$ip}'");
        }

        if ($this->redisHandler === null) {
            $duration = $this->clampToLocalCap($duration, 'not configured');
        }

        $expiry = microtime(true) + $duration;
        $this->bannedIps[$ip] = $expiry;
        $this->evictOverflow();

        if ($this->redisHandler !== null) {
            try {
                $this->redisHandler->setKey(self::BANNED_IPS_NAMESPACE, $ip, self::formatExpiry($expiry), $duration);
            } catch (GuardRedisException $e) {
                $duration = $this->clampToLocalCap($duration, 'request failed');
                $this->bannedIps[$ip] = microtime(true) + $duration;
            }
        }

        $this->events?->sendBanEvent($ip, $duration, $reason);
    }

    private function banCidr(string $ip, int $duration): void
    {
        try {
            $network = CanonicalIp::canonicalNetwork($ip);
        } catch (\InvalidArgumentException $e) {
            throw new \InvalidArgumentException("Invalid CIDR network '{$ip}': {$e->getMessage()}");
        }

        if ($this->redisHandler === null) {
            $duration = $this->clampToLocalCap($duration, 'not configured');
            $this->bannedNetworks[] = ['network' => $network, 'expiry' => microtime(true) + $duration];

            return;
        }

        try {
            $this->redisHandler->setKey(
                self::BANNED_NETWORKS_NAMESPACE,
                $network,
                self::formatExpiry(microtime(true) + $duration),
                $duration
            );
        } catch (GuardRedisException $e) {
            $duration = $this->clampToLocalCap($duration, 'request failed');
            $this->bannedNetworks[] = ['network' => $network, 'expiry' => microtime(true) + $duration];
        }
    }

    private function checkRedisExact(string $ip, float $now): bool
    {
        $expiry = $this->redisHandler->getKey(self::BANNED_IPS_NAMESPACE, $ip);
        if ($expiry === null || $expiry === '') {
            return false;
        }
        $expiryTime = (float) $expiry;
        if ($now <= $expiryTime) {
            $this->bannedIps[$ip] = $expiryTime;

            return true;
        }
        $this->redisHandler->delete(self::BANNED_IPS_NAMESPACE, $ip);

        return false;
    }

    private function checkNetworkCache(string $addr, float $now): bool
    {
        $active = [];
        $hit = false;
        foreach ($this->bannedNetworks as $entry) {
            if ($entry['expiry'] <= $now) {
                continue;
            }
            $active[] = $entry;
            if (!$hit && CanonicalIp::networkContains($entry['network'], $addr)) {
                $hit = true;
            }
        }
        $this->bannedNetworks = $active;

        return $hit;
    }

    private function clampToLocalCap(int $duration, string $cause): int
    {
        if ($duration <= self::LOCAL_CACHE_TTL_CAP_SECONDS) {
            return $duration;
        }
        $this->emitWarning("Redis unavailable ({$cause}): ban shortened from {$duration}s to "
            . self::LOCAL_CACHE_TTL_CAP_SECONDS . 's so protection still applies');

        return self::LOCAL_CACHE_TTL_CAP_SECONDS;
    }

    private function selfDosRefusalReason(string $ip): ?string
    {
        $target = self::parseNetwork($ip);
        if ($target === null) {
            return null;
        }
        if (self::networksOverlap($target, '127.0.0.0/8') || self::networksOverlap($target, '::1/128')) {
            return 'loopback';
        }
        foreach ($this->trustedProxyNetworks as $proxy) {
            if (self::networksOverlap($target, $proxy)) {
                return 'trusted_proxy';
            }
        }

        return null;
    }

    private function evictOverflow(): void
    {
        while (count($this->bannedIps) > self::MAX_LOCAL_ENTRIES) {
            foreach ($this->bannedIps as $key => $_) {
                unset($this->bannedIps[$key]);
                break;
            }
        }
    }

    private function migrateLegacyBanKeys(): bool
    {
        if ($this->redisHandler === null) {
            return true;
        }
        $prefix = $this->redisHandler->prefix() . self::BANNED_IPS_NAMESPACE . ':';
        try {
            $conn = $this->redisHandler->connection();
            $cursor = '0';
            do {
                [$cursor, $keys] = $conn->scan($cursor, $prefix . '*');
                foreach ($keys as $key) {
                    $this->migrateOneBanKey($conn, $key, $prefix);
                }
            } while ($cursor !== '0');

            return true;
        } catch (\Throwable $e) {
            $this->emitWarning('Legacy ban-key migration skipped: ' . $e->getMessage());

            return false;
        }
    }

    private function migrateOneBanKey(
        \RenzoFranceschini\GuardCore\Redis\RespConnection $conn,
        string $key,
        string $prefix
    ): void {
        $rawIp = substr($key, strlen($prefix));
        $canonicalIp = CanonicalIp::canonicalize($rawIp);
        if ($canonicalIp === $rawIp) {
            return;
        }

        $pipe = $conn->pipeline();
        $pipe->get($key);
        $pipe->pttl($key);
        $result = $pipe->execute();
        $value = $result[0] ?? null;
        $oldPttl = (int) ($result[1] ?? 0);

        if ($oldPttl <= 0) {
            $conn->del($key);

            return;
        }

        $canonicalKey = $prefix . $canonicalIp;
        $newPttl = $conn->pttl($canonicalKey);
        if ($newPttl < $oldPttl) {
            $conn->set($canonicalKey, strval($value), px: $oldPttl);
        }
        $conn->del($key);
    }

    private function emitWarning(string $message): void
    {
        if ($this->warn !== null) {
            ($this->warn)($message);
        }
    }

    public static function formatExpiry(float $expiry): string
    {
        return var_export($expiry, true);
    }

    /** @return array{0: string, 1: int}|null [ip text, prefix length] */
    private static function parseNetwork(string $value): ?array
    {
        $slash = strrpos($value, '/');
        if ($slash !== false) {
            $addr = CanonicalIp::parse(substr($value, 0, $slash));
            $prefix = filter_var(substr($value, $slash + 1), FILTER_VALIDATE_INT);
            if ($addr === null || $prefix === false) {
                return null;
            }
            $bits = str_contains($addr, ':') ? 128 : 32;
            if ($prefix < 0 || $prefix > $bits) {
                return null;
            }

            return [$addr, $prefix];
        }
        $addr = CanonicalIp::parse($value);
        if ($addr === null) {
            return null;
        }

        return [$addr, str_contains($addr, ':') ? 128 : 32];
    }

    private static function isNetwork(string $value): bool
    {
        $parsed = self::parseNetwork($value);

        return $parsed !== null;
    }

    private static function networksOverlap(array $a, string $b): bool
    {
        $bParsed = self::parseNetwork($b);
        if ($bParsed === null) {
            return false;
        }
        $aBytes = @inet_pton($a[0]);
        $bBytes = @inet_pton($bParsed[0]);
        if ($aBytes === false || $bBytes === false || strlen($aBytes) !== strlen($bBytes)) {
            return false;
        }
        $lo = function (string $bytes, int $prefix): string {
            return CanonicalIp::maskBytes($bytes, $prefix);
        };
        $hi = function (string $bytes, int $prefix): string {
            $masked = CanonicalIp::maskBytes($bytes, $prefix);
            $lastByteIndex = (int) ceil($prefix / 8) - 1;
            if ($lastByteIndex < 0) {
                return $masked;
            }
            $remBits = $prefix % 8;
            if ($remBits === 0) {
                return $masked;
            }
            $masked[$lastByteIndex] = chr(ord($masked[$lastByteIndex]) | (0xff >> $remBits));

            return $masked;
        };

        return strcmp($lo($aBytes, $a[1]), $hi($bBytes, $bParsed[1])) <= 0
            && strcmp($lo($bBytes, $bParsed[1]), $hi($aBytes, $a[1])) <= 0;
    }

    private static function isPrivateNetwork(array $network): bool
    {
        [$addr, $prefix] = $network;
        $bytes = @inet_pton($addr);
        if ($bytes === false) {
            return false;
        }
        if (strlen($bytes) === 4) {
            $o = array_values(unpack('C4', $bytes));
            return $o[0] === 10
                || ($o[0] === 172 && $o[1] >= 16 && $o[1] <= 31)
                || ($o[0] === 192 && $o[1] === 168)
                || ($o[0] === 169 && $o[1] === 254);
        }
        $hex = bin2hex($bytes);

        return str_starts_with($hex, 'fe80')
            || str_starts_with($hex, 'fc') || str_starts_with($hex, 'fd')
            || self::isV4CompatPrivate($bytes);
    }

    private static function isV4CompatPrivate(string $bytes16): bool
    {
        if (substr($bytes16, 0, 10) !== str_repeat("\x00", 10)
            || substr($bytes16, 10, 2) !== "\xff\xff") {
            return false;
        }
        $o = array_values(unpack('C4', substr($bytes16, 12, 4)));

        return $o[0] === 10
            || ($o[0] === 172 && $o[1] >= 16 && $o[1] <= 31)
            || ($o[0] === 192 && $o[1] === 168);
    }
}
