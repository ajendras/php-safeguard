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
        $expressions = $this->getOutputExpressions($node);
        if ($expressions === []) {
            return null;
        }

        foreach ($expressions as $expr) {
            if ($this->isEscaped($expr)) {
                continue;
            }

            if ($this->containsTaintedData($expr)) {
                return new Finding(
                    rule: 'xss',
                    message: 'Potential XSS: unsanitized data is being output directly',
                    file: $ctx->file,
                    line: $ctx->line,
                    severity: 'high',
                    snippet: $this->extractSnippet($ctx->source, $ctx->line),
                    suggestion: 'Escape output using htmlspecialchars((string) $var, ENT_QUOTES | ENT_SUBSTITUTE, \'UTF-8\') or Laravel\'s e() helper. Prefer template engines with auto-escaping (Blade {{ }}) over raw output.'
                );
            }
        }

        return null;
    }

    private function getOutputExpressions(Node $node): array
    {
        if ($node instanceof Stmt\Echo_) {
            return $node->exprs;
        }

        if ($node instanceof Expr\Print_) {
            return [$node->expr];
        }

        return [];
    }

    private function isEscaped(Node $node): bool
    {
        if (!$node instanceof Expr\FuncCall || !$node->name instanceof Name) {
            return false;
        }

        $funcName = strtolower($node->name->toString());
        return in_array($funcName, self::ESCAPING_FUNCTIONS, true);
    }

    private function containsTaintedData(Node $node): bool
    {
        if ($node instanceof Expr\Variable) {
            return true;
        }

        if ($node instanceof Expr\MethodCall || $node instanceof Expr\StaticCall) {
            return true;
        }

        if ($node instanceof Expr\ArrayDimFetch) {
            return true;
        }

        if ($node instanceof BinaryOp\Concat) {
            return $this->containsTaintedData($node->left) || $this->containsTaintedData($node->right);
        }

        if ($node instanceof Scalar\InterpolatedString) {
            foreach ($node->parts as $part) {
                if (!$part instanceof Scalar\String_) {
                    return true;
                }
            }
            return false;
        }

        if ($node instanceof Expr\FuncCall) {
            // function calls are considered tainted unless it's an escaping function (already checked)
            return true;
        }

        return false;
    }

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
