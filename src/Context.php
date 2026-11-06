<?php

declare(strict_types=1);

namespace PhpSafeguard;

/**
 * Immutable context object passed to each rule during AST traversal.
 *
 * Contains the current file being scanned, the full source code (for
 * snippet extraction) and the line number of the visited node.
 */
final class Context
{
    public function __construct(
        public readonly string $file,
        public readonly string $source,
        public readonly int $line,
    ) {}
}
