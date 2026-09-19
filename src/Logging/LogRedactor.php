<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Logging;

final class LogRedactor
{
    public const DEFAULT_SENSITIVE_HEADERS = ['authorization', 'proxy-authorization', 'cookie', 'x-api-key'];

    public const DEFAULT_SENSITIVE_FIELDS = [
        'access_token', 'refresh_token', 'api_key', 'apikey', 'token',
        'password', 'secret', 'client_secret', 'signature',
    ];

    /**
     * @param list<string> $defaults
     * @param list<string>|null $extra
     * @return list<string>
     */
    public static function mergeNames(array $defaults, ?array $extra): array
    {
        if ($extra === null) {
            return $defaults;
        }
        $merged = [];
        foreach ([...$defaults, ...$extra] as $name) {
            $lower = strtolower($name);
            if (!in_array($lower, $merged, true)) {
                $merged[] = $lower;
            }
        }

        return $merged;
    }

    /**
     * Sensitive header names become '[REDACTED]'; every other header value is
     * passed through blob redaction (JSON / percent-encoded JSON / XML
     * elements / key=value pairs).
     *
     * @param array<string, string> $headers
     * @param list<string>|null $extraHeaders
     * @param list<string>|null $extraBodyFields
     * @param list<string>|null $extraParams
     * @return array<string, string>
     */
    public static function redactHeaders(
        array $headers,
        ?array $extraHeaders = null,
        ?array $extraBodyFields = null,
        ?array $extraParams = null
    ): array {
        $sensitive = self::mergeNames(self::DEFAULT_SENSITIVE_HEADERS, $extraHeaders);
        $sensitiveValues = self::mergedSensitiveNames($extraParams, $extraBodyFields, $extraHeaders);
        $out = [];
        foreach ($headers as $name => $value) {
            $out[$name] = in_array(strtolower(trim((string) $name)), $sensitive, true)
                ? '[REDACTED]'
                : self::redactBlob((string) $value, $sensitiveValues);
        }

        return $out;
    }

    /**
     * @param list<string>|null $extraParams
     * @param list<string>|null $extraBodyFields
     * @param list<string>|null $extraHeaders
     */
    public static function redactUrlForDisplay(
        string $url,
        ?array $extraParams = null,
        ?array $extraBodyFields = null,
        ?array $extraHeaders = null
    ): string {
        $escaped = str_replace(["\t", "\r", "\n"], ['%09', '%0D', '%0A'], $url);
        $parts = parse_url($escaped);
        if ($parts === false) {
            return $escaped;
        }
        $sensitive = self::mergedSensitiveNames($extraParams, $extraBodyFields, $extraHeaders);

        $scheme = isset($parts['scheme']) ? $parts['scheme'] . '://' : '';
        $netloc = $parts['host'] ?? '';
        if (isset($parts['port'])) {
            $netloc .= ':' . $parts['port'];
        }
        if (isset($parts['user'])) {
            $userinfo = $parts['user'];
            if (isset($parts['pass'])) {
                $userinfo .= ':[REDACTED]';
            }
            $netloc = $userinfo . '@' . $netloc;
        }
        $path = self::redactPath($parts['path'] ?? '', $sensitive);
        $query = self::redactPairs($parts['query'] ?? '', $sensitive);
        $fragment = self::redactPairs($parts['fragment'] ?? '', $sensitive);

        $out = $scheme . $netloc . $path;
        if ($query !== '') {
            $out .= '?' . $query;
        }
        if ($fragment !== '') {
            $out .= '#' . $fragment;
        }

        return $out;
    }

    /**
     * Redacts `key=value` pairs separated by `&`, `;`, or `/`, percent-decodes
     * keys before matching, and leaves tokens without `=` untouched.
     */
    public static function redactPairs(string $text, array $sensitive): string
    {
        if ($text === '' || !self::hasAssign($text)) {
            return $text;
        }

        return preg_replace_callback(
            '/([^&;=\/]+)=([^&;\/]*)/',
            function (array $m) use ($sensitive): string {
                $key = strtolower(trim(urldecode($m[1])));

                return in_array($key, $sensitive, true) ? $m[1] . '=[REDACTED]' : $m[0];
            },
            $text
        ) ?? $text;
    }

    /**
     * JSON object/array redaction when the text (or its percent-decoded form)
     * parses; otherwise XML element redaction, then pair redaction. The
     * sensitive name set is the shared defaults merged with the config sets.
     *
     * @param list<string>|null $extraParams
     * @param list<string>|null $extraBodyFields
     * @param list<string>|null $extraHeaders
     */
    public static function redactBlob(
        string $text,
        ?array $extraParams = null,
        ?array $extraBodyFields = null,
        ?array $extraHeaders = null
    ): string {
        if ($text === '') {
            return $text;
        }
        $sensitive = self::mergedSensitiveNames($extraParams, $extraBodyFields, $extraHeaders);
        $json = self::redactJsonText($text, $sensitive);
        if ($json !== null) {
            return $json;
        }
        $json = self::redactJsonText(rawurldecode($text), $sensitive);
        if ($json !== null) {
            return $json;
        }
        $xml = self::redactXmlElements($text, $sensitive);

        return self::redactPairs($xml, $sensitive);
    }

    /** @return list<string> */
    public static function sensitiveNames(?array $extraParams, ?array $extraBodyFields, ?array $extraHeaders = null): array
    {
        return self::mergedSensitiveNames($extraParams, $extraBodyFields, $extraHeaders);
    }

    /**
     * @param list<string>|null $extraParams
     * @param list<string>|null $extraBodyFields
     * @param list<string>|null $extraHeaders
     * @return list<string>
     */
    private static function mergedSensitiveNames(?array $extraParams, ?array $extraBodyFields, ?array $extraHeaders): array
    {
        $fields = self::mergeNames(self::DEFAULT_SENSITIVE_FIELDS, $extraParams);
        if ($extraBodyFields !== null) {
            foreach ($extraBodyFields as $name) {
                $lower = strtolower($name);
                if (!in_array($lower, $fields, true)) {
                    $fields[] = $lower;
                }
            }
        }
        foreach (self::mergeNames(self::DEFAULT_SENSITIVE_HEADERS, $extraHeaders) as $name) {
            if (!in_array($name, $fields, true)) {
                $fields[] = $name;
            }
        }

        return $fields;
    }

    private static function hasAssign(string $text): bool
    {
        return str_contains($text, '=');
    }

    /** @param list<string> $sensitive */
    private static function redactJsonText(string $text, array $sensitive): ?string
    {
        if ($text === '' || ($text[0] !== '{' && $text[0] !== '[')) {
            return null;
        }
        try {
            $parsed = json_decode($text, true, 64, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            return null;
        }
        if (!is_array($parsed)) {
            return null;
        }
        $changed = false;
        $redacted = self::redactJsonTree($parsed, $sensitive, $changed);
        if (!$changed) {
            return null;
        }

        return (string) json_encode($redacted, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    }

    private static function redactJsonTree(mixed $value, array $sensitive, bool &$changed, int $depth = 0): mixed
    {
        if ($depth > 64) {
            return null;
        }
        if (is_array($value)) {
            $out = [];
            foreach ($value as $key => $child) {
                if (is_string($key) && in_array(strtolower($key), $sensitive, true)) {
                    $out[$key] = '[REDACTED]';
                    $changed = true;
                } else {
                    $out[$key] = self::redactJsonTree($child, $sensitive, $changed, $depth + 1);
                }
            }

            return $out;
        }

        return $value;
    }

    /** @param list<string> $sensitive */
    private static function redactXmlElements(string $text, array $sensitive): string
    {
        return preg_replace_callback(
            '/<([A-Za-z_][\w.:-]*)>([^<]*)<\/\1>/',
            function (array $m) use ($sensitive): string {
                if (!in_array(strtolower($m[1]), $sensitive, true)) {
                    return $m[0];
                }

                return '<' . $m[1] . '>[REDACTED]</' . $m[1] . '>';
            },
            $text
        ) ?? $text;
    }

    /** @param list<string> $sensitive */
    private static function redactPath(string $path, array $sensitive): string
    {
        if ($path === '' || !self::hasAssign($path)) {
            return $path;
        }

        return implode('/', array_map(
            fn (string $segment): string => self::redactPairs($segment, $sensitive),
            explode('/', $path)
        ));
    }
}
