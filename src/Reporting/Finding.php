<?php

declare(strict_types=1);

namespace PhpSafeguard\Reporting;

/**
 * Immutable value object representing a single security finding.
 *
 * Holds all information required by Report for console, JSON and SARIF
 * output including rule name, severity, location, snippet and suggestion.
 */
final class Finding
{
    public function __construct(
        public readonly string $rule,
        public readonly string $message,
        public readonly string $file,
        public readonly int $line,
        public readonly string $severity,
        public readonly ?string $snippet = null,
        public readonly ?string $suggestion = null,
    ) {}
}
