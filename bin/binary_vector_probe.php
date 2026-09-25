<?php

declare(strict_types=1);

/**
 * Binary-body detect vector probe for the interop binary-vector runner
 * (interop/go_php_binary_vectors.py in the guard-core reference checkout).
 *
 * Reads a JSON vector list from the path in INTEROP_VECTORS_INPUT (each
 * vector: {"label": ..., "payload_b64": ...} with an optional "context"
 * detect context, defaulting to "request_body:multipart_field"; the payload
 * bytes are the raw request body bytes) and writes one verdict per vector to
 * the path in INTEROP_VECTORS_OUTPUT:
 *
 *     {"label": ..., "is_threat": ..., "threat_score": ...,
 *      "threats": [{"category": ..., "pattern": ...}]}
 *
 * Body bytes become a UTF-8 PHP string with invalid bytes mapped to U+FFFD
 * (one code point per invalid byte, mirroring the mbstring-based Text
 * helpers), the engine's own binary-body representation.
 */

use RenzoFranceschini\GuardCore\Detection\SusPatterns;

require __DIR__ . '/../vendor/autoload.php';

function binaryVectorInvalidToReplacement(string $raw): string
{
    $out = '';
    $n = strlen($raw);
    $i = 0;
    while ($i < $n) {
        $byte = ord($raw[$i]);
        if ($byte < 0x80) {
            $out .= $raw[$i];
            $i++;
            continue;
        }
        if (($byte >= 0xc2 && $byte <= 0xdf) && $i + 1 < $n && (ord($raw[$i + 1]) & 0xc0) === 0x80) {
            $out .= substr($raw, $i, 2);
            $i += 2;
            continue;
        }
        if (($byte >= 0xe0 && $byte <= 0xef) && $i + 2 < $n && (ord($raw[$i + 1]) & 0xc0) === 0x80 && (ord($raw[$i + 2]) & 0xc0) === 0x80) {
            $cp = (($byte & 0x0f) << 12) | ((ord($raw[$i + 1]) & 0x3f) << 6) | (ord($raw[$i + 2]) & 0x3f);
            if ($cp >= 0x800 && ($cp < 0xd800 || $cp > 0xdfff)) {
                $out .= substr($raw, $i, 3);
                $i += 3;
                continue;
            }
        }
        if (($byte >= 0xf0 && $byte <= 0xf4) && $i + 3 < $n && (ord($raw[$i + 1]) & 0xc0) === 0x80 && (ord($raw[$i + 2]) & 0xc0) === 0x80 && (ord($raw[$i + 3]) & 0xc0) === 0x80) {
            $cp = (($byte & 0x07) << 18) | ((ord($raw[$i + 1]) & 0x3f) << 12) | ((ord($raw[$i + 2]) & 0x3f) << 6) | (ord($raw[$i + 3]) & 0x3f);
            if ($cp >= 0x10000 && $cp <= 0x10ffff) {
                $out .= substr($raw, $i, 4);
                $i += 4;
                continue;
            }
        }
        $out .= "\u{fffd}";
        $i++;
    }

    return $out;
}

$inputPath = getenv('INTEROP_VECTORS_INPUT');
$outputPath = getenv('INTEROP_VECTORS_OUTPUT');
if ($inputPath === false || $inputPath === '' || $outputPath === false || $outputPath === '') {
    fwrite(STDERR, "INTEROP_VECTORS_INPUT and INTEROP_VECTORS_OUTPUT must be set\n");
    exit(2);
}
$raw = file_get_contents($inputPath);
if ($raw === false) {
    fwrite(STDERR, "cannot read {$inputPath}\n");
    exit(2);
}
$vectors = json_decode($raw, true);
if (! is_array($vectors)) {
    fwrite(STDERR, "vectors input is not valid JSON\n");
    exit(2);
}

$sus = new SusPatterns();
$out = [];
foreach ($vectors as $vector) {
    $payload = base64_decode($vector['payload_b64'], true);
    if ($payload === false) {
        fwrite(STDERR, "vector {$vector['label']} payload_b64 is not valid base64\n");
        exit(2);
    }
    $context = (string) ($vector['context'] ?? '');
    if ($context === '') {
        $context = 'request_body:multipart_field';
    }
    $result = $sus->detect(binaryVectorInvalidToReplacement($payload), '127.0.0.1', $context);
    $threats = [];
    foreach ($result['threats'] as $threat) {
        $threats[] = [
            'category' => (string) ($threat['category'] ?? ''),
            'pattern' => (string) ($threat['pattern'] ?? ''),
        ];
    }
    usort($threats, static fn (array $a, array $b): int => [$a['category'], $a['pattern']] <=> [$b['category'], $b['pattern']]);
    $out[] = [
        'label' => $vector['label'],
        'is_threat' => (bool) $result['is_threat'],
        'threat_score' => (float) $result['threat_score'],
        'threats' => $threats,
        'original_length' => (int) $result['original_length'],
    ];
}
file_put_contents($outputPath, json_encode($out, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n");
