<?php

declare(strict_types=1);

namespace PhpSafeguard\Rules;

use PhpParser\Node;
use PhpParser\Node\Expr;
use PhpParser\Node\Expr\BinaryOp;
use PhpParser\Node\Name;
use PhpParser\Node\Scalar;
use PhpParser\Node\Stmt;
use PhpSafeguard\Context;
use PhpSafeguard\Reporting\Finding;

/**
 * Detects reflected or stored XSS by identifying output of unsanitized data.
 *
 * Looks for echo, print, <?= ?> and similar constructs where a variable,
 * concatenation, or property is sent to the browser without an escaping
 * function (htmlspecialchars, htmlentities, Laravel's e() helper, etc.).
 */
final class XssRule implements RuleInterface
{
    /**
     * Known safe escaping functions.
     *
     * @var list<string>
     */
    private const ESCAPING_FUNCTIONS = [
        'htmlspecialchars',
        'htmlentities',
        'e',                    // Laravel helper
        'esc_html',             // Common in WordPress plugins
        'h',                    // CakePHP
        'filter_var',
    ];

    public function detect(Node $node, Context $ctx): ?Finding
    {
        if (!($node instanceof Stmt\Echo_ || $node instanceof Expr\Print_)) {
            return null;
        }

        $expressions = $node instanceof Stmt\Echo_
            ? $node->exprs
            : [$node->expr];

        foreach ($expressions as $expr) {
            if ($this->isUnsanitizedOutput($expr)) {
                return new Finding(
                    rule: 'xss',
                    message: 'Potential XSS: unsanitized data is being output directly',
                    file: $ctx->file,
                    line: $ctx->line,
                    severity: 'high',
                    snippet: $this->extractSnippet($ctx->source, $ctx->line),
                    suggestion: 'Wrap the output with htmlspecialchars(): htmlspecialchars((string) $var, ENT_QUOTES | ENT_SUBSTITUTE, \'UTF-8\') or use a templating engine with auto-escaping.'
                );
            }
        }

        return null;
    }

    /**
     * Determines whether an expression represents unsanitized output.
     */
    private function isUnsanitizedOutput(Node $node): bool
    {
        // Literals are safe
        if ($node instanceof Scalar\String_ ||
            $node instanceof Scalar\Int_ ||
            $node instanceof Scalar\Float_ ||
            $node instanceof Scalar\DNumber) {
            return false;
        }

        // Direct variables, array access, or object properties are dangerous
        if ($node instanceof Expr\Variable ||
            $node instanceof Expr\ArrayDimFetch ||
            $node instanceof Expr\PropertyFetch) {
            return true;
        }

        // Function calls: safe only if they are escaping functions
        if ($node instanceof Expr\FuncCall && $node->name instanceof Name) {
            $functionName = strtolower($node->name->toString());
            return !in_array($functionName, self::ESCAPING_FUNCTIONS, true);
        }

        // Concatenation is unsafe if any part is unsafe
        if ($node instanceof BinaryOp\Concat) {
            return $this->isUnsanitizedOutput($node->left) ||
                   $this->isUnsanitizedOutput($node->right);
        }

        // Method calls on objects (e.g. $obj->getHtml()) are treated as risky
        if ($node instanceof Expr\MethodCall) {
            return true;
        }

        // Unknown constructs inside output statements are conservatively flagged
        return true;
    }

    /**
     * Extracts the source line that triggered the finding.
     */
    private function extractSnippet(string $source, int $line): string
    {
        $lines = preg_split('/\r\n?|\n/', $source);
        $index = $line - 1;

        if (isset($lines[$index])) {
            return trim($lines[$index]);
        }

        return '';
    }
}
