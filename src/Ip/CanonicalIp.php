<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Ip;

final class CanonicalIp
{
    public static function stripBrackets(string $value): string
    {
        if (str_starts_with($value, '[') && str_ends_with($value, ']')) {
            return substr($value, 1, -1);
        }

        return $value;
    }

    public static function canonicalize(string $value): string
    {
        $stripped = self::stripBrackets($value);
        $scopePos = strpos($stripped, '%');
        if ($scopePos !== false) {
            $addrPart = substr($stripped, 0, $scopePos);
            $scope = substr($stripped, $scopePos + 1);
            $text = self::canonicalText($addrPart, allowV4MappedCollapse: false);
            if ($text === null) {
                return $value;
            }

            return $text . '%' . $scope;
        }
        $text = self::canonicalText($stripped);

        return $text ?? $value;
    }

    public static function parse(string $value): ?string
    {
        return self::canonicalText(self::stripBrackets($value));
    }

    public static function canonicalNetwork(string $cidr): string
    {
        $slash = strrpos($cidr, '/');
        if ($slash === false) {
            throw new \InvalidArgumentException("Invalid CIDR network '{$cidr}': missing prefix length");
        }
        $addrPart = substr($cidr, 0, $slash);
        $prefixLen = filter_var(substr($cidr, $slash + 1), FILTER_VALIDATE_INT);
        $addr = self::canonicalText(self::stripBrackets($addrPart));
        if ($addr === null || $prefixLen === false) {
            throw new \InvalidArgumentException("Invalid CIDR network '{$cidr}'");
        }
        $bytes = @inet_pton($addr);
        if ($bytes === false) {
            throw new \InvalidArgumentException("Invalid CIDR network '{$cidr}'");
        }
        $totalBits = strlen($bytes) * 8;
        if ($prefixLen < 0 || $prefixLen > $totalBits) {
            throw new \InvalidArgumentException("Invalid CIDR network '{$cidr}': prefix length out of range");
        }
        $masked = self::clearHostBits($bytes, $prefixLen);

        return self::bytesToText($masked, isV4: strlen($bytes) === 4) . '/' . $prefixLen;
    }

    public static function networkContains(string $network, string $ip): bool
    {
        $slash = strrpos($network, '/');
        if ($slash === false) {
            return false;
        }
        $prefixLen = (int) substr($network, $slash + 1);
        $netBytes = @inet_pton(substr($network, 0, $slash));
        $ipBytes = @inet_pton($ip);
        if ($netBytes === false || $ipBytes === false || strlen($netBytes) !== strlen($ipBytes)) {
            return false;
        }

        return substr(self::clearHostBits($ipBytes, $prefixLen), 0, (int) ceil($prefixLen / 8))
            === substr(self::clearHostBits($netBytes, $prefixLen), 0, (int) ceil($prefixLen / 8));
    }

    public static function isLoopback(string $ip): bool
    {
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return str_starts_with($ip, '127.');
        }
        $bytes = @inet_pton($ip);
        if ($bytes === false || strlen($bytes) !== 16) {
            return false;
        }

        return $bytes === inet_pton('::1') || self::isV4Mapped($bytes)
            && str_starts_with(inet_ntop(substr($bytes, 12, 4)), '127.');
    }

    private static function canonicalText(string $value, bool $allowV4MappedCollapse = true): ?string
    {
        if (filter_var($value, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return $value;
        }
        if (!filter_var($value, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            return null;
        }
        $bytes = @inet_pton($value);
        if ($bytes === false || strlen($bytes) !== 16) {
            return null;
        }
        if ($allowV4MappedCollapse && self::isV4Mapped($bytes)) {
            return inet_ntop(substr($bytes, 12, 4));
        }

        return self::bytesToText($bytes, isV4: false);
    }

    private static function isV4Mapped(string $bytes16): bool
    {
        return substr($bytes16, 0, 10) === str_repeat("\x00", 10)
            && substr($bytes16, 10, 2) === "\xff\xff";
    }

    public static function maskBytes(string $bytes, int $prefixLen): string
    {
        return self::clearHostBits($bytes, $prefixLen);
    }

    private static function clearHostBits(string $bytes, int $prefixLen): string
    {
        $out = $bytes;
        $fullBytes = intdiv($prefixLen, 8);
        $remBits = $prefixLen % 8;
        for ($i = $fullBytes + ($remBits > 0 ? 1 : 0); $i < strlen($bytes); $i++) {
            $out[$i] = "\x00";
        }
        if ($remBits > 0) {
            $mask = (0xff << (8 - $remBits)) & 0xff;
            $out[$fullBytes] = chr(ord($out[$fullBytes]) & $mask);
        }

        return $out;
    }

    private static function bytesToText(string $bytes, bool $isV4): string
    {
        if ($isV4) {
            return inet_ntop($bytes);
        }
        $groups = array_values(unpack('n8', $bytes));
        $hex = array_map(dechex(...), $groups);
        $bestStart = -1;
        $bestLen = 0;
        $curStart = -1;
        $curLen = 0;
        foreach ($groups as $i => $g) {
            if ($g === 0) {
                if ($curStart === -1) {
                    $curStart = $i;
                    $curLen = 1;
                } else {
                    $curLen++;
                }
                if ($curLen > $bestLen) {
                    $bestStart = $curStart;
                    $bestLen = $curLen;
                }
            } else {
                $curStart = -1;
                $curLen = 0;
            }
        }
        if ($bestLen < 2) {
            return implode(':', $hex);
        }
        $left = implode(':', array_slice($hex, 0, $bestStart));
        $right = implode(':', array_slice($hex, $bestStart + $bestLen));

        return $left . '::' . $right;
    }
}
