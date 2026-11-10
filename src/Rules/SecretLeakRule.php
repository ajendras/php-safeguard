<?php

declare(strict_types=1);

namespace PhpSafeguard\Rules;

use PhpParser\Node;
use PhpParser\Node\Expr;
use PhpParser\Node\Scalar;
use PhpSafeguard\Context;
use PhpSafeguard\Reporting\Finding;

/**
 * Detects potential secret leaks such as API keys, passwords and tokens.
 *
 * Uses a combination of regex patterns for known secret formats (AWS, Stripe,
 * GitHub, etc.) and Shannon entropy calculation on long strings. Also inspects
 * assignments to sensitive variable names and array keys containing secrets.
 */
final class SecretLeakRule implements RuleInterface
{
    /**
     * Minimum length for entropy-based secret detection.
     */
    private const MIN_SECRET_LENGTH = 12;

    /**
     * Entropy threshold (bits per character).
     */
    private const ENTROPY_THRESHOLD = 4.0;

    /**
     * Known sensitive variable and key names (case-insensitive partial match).
     *
     * @var list<string>
     */
    private const SENSITIVE_NAMES = [
        'password', 'passwd', 'pwd', 'secret', 'key', 'token', 'api_key',
        'apikey', 'access_key', 'private_key', 'auth', 'credential', 'bearer',
    ];

    /**
     * Regex patterns for common secret formats.
     *
     * @var list<string>
     */
    private const SECRET_REGEXES = [
        '/AKIA[0-9A-Z]{16,}/',                  // AWS Access Key ID
        '/sk_live_[0-9a-zA-Z]{20,}/',          // Stripe secret key
        '/ghp_[0-9a-zA-Z]{36,}/',               // GitHub personal access token
        '/^eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}$/', // JWT
    ];

    public function detect(Node $node, Context $ctx): ?Finding
    {
        // $sensitive = "high-entropy-or-pattern-value";
        if ($node instanceof Expr\Assign) {
            $varName = $this->extractVariableName($node->var);
            if ($varName !== null && $this->isSensitiveName($varName)) {
                if ($node->expr instanceof Scalar\String_ && $this->isSecretValue($node->expr->value)) {
                    return $this->createFinding($ctx, $node->expr->value);
                }
            }
        }

        // 'password' => 'secretvalue' inside arrays
        if ($node instanceof Expr\ArrayItem && $node->key instanceof Scalar\String_) {
            $key = $node->key->value;
            if ($this->isSensitiveName($key) && $node->value instanceof Scalar\String_ && $this->isSecretValue($node->value->value)) {
                return $this->createFinding($ctx, $node->value->value);
            }
        }

        // Standalone high-entropy string literals (conservative: length > 32)
        if ($node instanceof Scalar\String_ && strlen($node->value) > 32 && $this->isSecretValue($node->value)) {
            return $this->createFinding($ctx, $node->value);
        }

        return null;
    }

    private function extractVariableName(Node $node): ?string
    {
        if ($node instanceof Expr\Variable && is_string($node->name)) {
            return $node->name;
        }

        return null;
    }

    private function isSensitiveName(string $name): bool
    {
        $lower = strtolower($name);
        foreach (self::SENSITIVE_NAMES as $sensitive) {
            if (str_contains($lower, $sensitive)) {
                return true;
            }
        }

        return false;
    }

    private function isSecretValue(string $value): bool
    {
        if (strlen($value) < self::MIN_SECRET_LENGTH) {
            return false;
        }

        foreach (self::SECRET_REGEXES as $regex) {
            if (preg_match($regex, $value) === 1) {
                return true;
            }
        }

        $entropy = $this->calculateEntropy($value);
        if ($entropy > self::ENTROPY_THRESHOLD) {
            return true;
        }

        return false;
    }

    private function calculateEntropy(string $string): float
    {
        $len = strlen($string);
        if ($len === 0) {
            return 0.0;
        }

        $frequencies = [];
        for ($i = 0; $i < $len; $i++) {
            $char = $string[$i];
            $frequencies[$char] = ($frequencies[$char] ?? 0) + 1;
        }

        $entropy = 0.0;
        foreach ($frequencies as $count) {
            $probability = $count / $len;
            $entropy -= $probability * log($probability, 2);
        }

        return $entropy;
    }

    private function createFinding(Context $ctx, string $secretValue): Finding
    {
        // Redact actual secret value in reports (security best practice)
        $redacted = substr($secretValue, 0, 8) . '...' . substr($secretValue, -4);

        return new Finding(
            rule: 'secret-leak',
            message: 'Potential secret leak: hardcoded credential or API key detected',
            file: $ctx->file,
            line: $ctx->line,
            severity: 'critical',
            snippet: $redacted,
            suggestion: 'Never commit secrets to version control. Use environment variables loaded via $_ENV, getenv(), or a .env library (e.g. vlucas/phpdotenv). Add sensitive files to .gitignore and consider a secret manager.'
        );
    }
}
