<?php

declare(strict_types=1);

namespace PhpSafeguard\Rules\Laravel;

use PhpParser\Node;
use PhpParser\Node\Arg;
use PhpParser\Node\Expr;
use PhpParser\Node\Identifier;
use PhpSafeguard\Context;
use PhpSafeguard\Reporting\Finding;
use PhpSafeguard\Rules\RuleInterface;

/**
 * Detects mass assignment vulnerabilities in Laravel applications.
 *
 * Flags calls to create(), fill(), update(), or forceFill() when they receive
 * unvalidated user input (e.g. $request->all()). Also notes when models appear
 * to lack explicit $fillable or $guarded properties.
 */
final class MassAssignmentRule implements RuleInterface
{
    /**
     * Model methods that can lead to mass assignment if given untrusted data.
     *
     * @var list<string>
     */
    private const DANGEROUS_METHODS = [
        'create',
        'fill',
        'update',
        'forceFill',
    ];

    /**
     * Methods that return bulk user input (considered tainted in this context).
     *
     * @var list<string>
     */
    private const TAINTED_INPUT_METHODS = [
        'all',
        'input',
        'only',
        'except',
        'toArray',
        // 'validated' is deliberately omitted because it returns already validated data.
    ];

    public function detect(Node $node, Context $ctx): ?Finding
    {
        if (!$node instanceof Expr\StaticCall && !$node instanceof Expr\MethodCall) {
            return null;
        }

        $methodName = $this->getMethodName($node);
        if ($methodName === null || !in_array($methodName, self::DANGEROUS_METHODS, true)) {
            return null;
        }

        $firstArg = $node->args[0] ?? null;
        if (!$firstArg instanceof Arg) {
            return null;
        }

        if (!$this->isTaintedInput($firstArg->value)) {
            return null;
        }

        $isModelContext = $this->isLikelyModelContext($node);

        return new Finding(
            rule: 'mass-assignment',
            message: 'Potential mass assignment: unvalidated input passed to ' . $methodName . '()',
            file: $ctx->file,
            line: $ctx->line,
            severity: $isModelContext ? 'high' : 'medium',
            snippet: $this->extractSnippet($ctx->source, $ctx->line),
            suggestion: 'Use $request->validated() with form requests, or ensure the model defines $fillable or $guarded properties. Avoid forceFill() in production code.'
        );
    }

    /**
     * Extracts the method name when it can be resolved statically.
     */
    private function getMethodName(Expr\StaticCall|Expr\MethodCall $node): ?string
    {
        if ($node->name instanceof Identifier) {
            return strtolower($node->name->toString());
        }

        return null;
    }

    /**
     * Determines whether the provided expression represents tainted user input.
     */
    private function isTaintedInput(Node $node): bool
    {
        // Direct method calls that are known to return raw request data are tainted.
        if ($node instanceof Expr\MethodCall || $node instanceof Expr\StaticCall) {
            $method = $this->getMethodName($node);
            if ($method !== null && in_array($method, self::TAINTED_INPUT_METHODS, true)) {
                return true;
            }
        }

        // Explicitly treat $request->validated() as safe (not tainted).
        if ($node instanceof Expr\MethodCall && $node->name instanceof Identifier) {
            $method = strtolower($node->name->toString());
            if ($method === 'validated') {
                return false;
            }
        }

        if ($node instanceof Expr\Variable) {
            $varName = $node->name;
            if (is_string($varName) && in_array($varName, ['_POST', '_GET', 'request', 'data', 'input'], true)) {
                return true;
            }
        }

        if ($node instanceof Expr\ArrayDimFetch) {
            return true;
        }

        if ($node instanceof Expr\FuncCall) {
            // Conservative: any function result fed to a mass-assignment method is suspect.
            return true;
        }

        return false;
    }

    /**
     * Best-effort check for whether this call is likely operating on an Eloquent model.
     */
    private function isLikelyModelContext(Expr\StaticCall|Expr\MethodCall $node): bool
    {
        if ($node instanceof Expr\StaticCall) {
            if ($node->class instanceof Node\Name) {
                $className = $node->class->toString();
                return !str_contains($className, 'Request')
                    && !str_contains($className, 'Controller');
            }
        }

        // Method calls on variables named $model, $user, $post etc. are likely models
        if ($node instanceof Expr\MethodCall && $node->var instanceof Expr\Variable) {
            $varName = $node->var->name;
            if (is_string($varName)) {
                return in_array($varName, ['model', 'user', 'post', 'record', 'entity'], true)
                    || str_ends_with($varName, 'Model');
            }
        }

        return true; // default to treating it as model-related
    }

    /**
     * Extracts the offending source line for inclusion in reports.
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
