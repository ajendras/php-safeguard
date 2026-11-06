<?php

declare(strict_types=1);

namespace PhpSafeguard\Rules;

use PhpParser\Node;
use PhpSafeguard\Context;
use PhpSafeguard\Reporting\Finding;

/**
 * Contract that all security detection rules must implement.
 *
 * Rules are applied to every AST node during traversal. If a node matches
 * a vulnerable pattern the rule returns a Finding; otherwise it returns null.
 */
interface RuleInterface
{
    /**
     * Analyze a single AST node for security issues.
     *
     * @param Node $node The node under inspection
     * @param Context $ctx File, source, and line context for the finding
     * @return Finding|null A Finding if a vulnerability was detected, otherwise null
     */
    public function detect(Node $node, Context $ctx): ?Finding;
}
