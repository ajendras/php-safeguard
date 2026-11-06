<?php

declare(strict_types=1);

namespace PhpSafeguard\Rules;

use PhpParser\Node;
use PhpParser\Node\Arg;
use PhpParser\Node\Expr;
use PhpParser\Node\Expr\BinaryOp;
use PhpParser\Node\Identifier;
use PhpParser\Node\Name;
use PhpSafeguard\Context;
use PhpSafeguard\Reporting\Finding;

/**
 * Detects SQL Injection risks from unsafe query construction.
 *
 * Flags use of DB::raw(), whereRaw(), query(), and similar methods when
 * the SQL string contains direct variable interpolation or concatenation
 * instead of bound parameters.
 */
final class SqlInjectionRule implements RuleInterface
{
    /**
     * Query builder / DB methods that accept raw SQL and are therefore dangerous
     * when variables are concatenated into them.
     *
     * @var list<string>
     */
    private const DANGEROUS_METHODS = [
        'raw',
        'selectRaw',
        'whereRaw',
        'orWhereRaw',
        'havingRaw',
        'orderByRaw',
        'query',
    ];

    public function detect(Node $node, Context $ctx): ?Finding
    {
        if (!$node instanceof Expr\StaticCall && !$node instanceof Expr\MethodCall) {
            return null;
        }

        $methodName = $this->getMethodName($node);
        if ($methodName === null || !$this->isDangerousMethod($methodName)) {
            return null;
        }

        if (!$this->isDatabaseRelatedCall($node)) {
            return null;
        }

        foreach ($node->args as $arg) {
            if (!$arg instanceof Arg) {
                continue;
            }

            if ($this->containsUnsanitizedInput($arg->value)) {
                return new Finding(
                    rule: 'sql-injection',
                    message: 'Potential SQL injection: raw query uses concatenated user input',
                    file: $ctx->file,
                    line: $ctx->line,
                    severity: 'critical',
                    snippet: $this->extractSnippet($ctx->source, $ctx->line),
                    suggestion: 'Use bound parameters or the query builder safely. Example: DB::select("SELECT * FROM users WHERE id = ?", [$id]); or $query->where("id", $id);'
                );
            }
        }

        return null;
    }

    /**
     * Returns the method name if it can be statically determined.
     */
    private function getMethodName(Expr\StaticCall|Expr\MethodCall $node): ?string
    {
        if ($node->name instanceof Identifier) {
            return strtolower($node->name->toString());
        }

        return null;
    }

    /**
     * Checks whether the method name matches one of our dangerous methods.
     */
    private function isDangerousMethod(string $methodName): bool
    {
        return in_array($methodName, self::DANGEROUS_METHODS, true);
    }

    /**
     * Determines if the call is related to a database / query builder.
     *
     * Accepts static calls on DB, Illuminate\Database, or any method call
     * on a query builder (common in Laravel Eloquent).
     */
    private function isDatabaseRelatedCall(Expr\StaticCall|Expr\MethodCall $node): bool
    {
        if ($node instanceof Expr\StaticCall) {
            if ($node->class instanceof Name) {
                $className = $node->class->toString();
                return str_ends_with($className, 'DB')
                    || str_ends_with($className, '\DB')
                    || str_contains($className, 'Database');
            }
            return false;
        }

        // MethodCall on $query, $model, $db, etc. is assumed to be query builder
        return true;
    }

    /**
     * Recursively checks whether an expression contains unsanitized user input.
     */
    private function containsUnsanitizedInput(Node $node): bool
    {
        if ($node instanceof Expr\Variable) {
            return true;
        }

        if ($node instanceof Expr\ArrayDimFetch || $node instanceof Expr\PropertyFetch) {
            // $_GET, $request->input(), $user->name etc.
            return true;
        }

        if ($node instanceof BinaryOp\Concat) {
            return $this->containsUnsanitizedInput($node->left) ||
                   $this->containsUnsanitizedInput($node->right);
        }

        if ($node instanceof Expr\FuncCall && $node->name instanceof Name) {
            $func = strtolower($node->name->toString());
            // Known safe wrappers still require scrutiny if they wrap a variable
            return !in_array($func, ['intval', 'strval', '(int)', '(string)'], true);
        }

        if ($node instanceof Expr\MethodCall) {
            // e.g. $request->get('id') - still treated as tainted for SQL context
            return true;
        }

        return false;
    }

    /**
     * Extracts the relevant source line for the report.
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
