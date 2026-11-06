<?php

declare(strict_types=1);

namespace PhpSafeguard\Scanners;

use PhpParser\Error;
use PhpParser\Node;
use PhpParser\NodeTraverser;
use PhpParser\NodeVisitorAbstract;
use PhpParser\ParserFactory;
use PhpSafeguard\Context;
use PhpSafeguard\Reporting\Finding;
use PhpSafeguard\Rules\RuleInterface;

/**
 * Performs static analysis using an Abstract Syntax Tree.
 *
 * Parses PHP files with nikic/php-parser, traverses the AST with a visitor
 * that invokes each registered RuleInterface implementation, and aggregates
 * any returned Finding objects.
 */
final class AstScanner
{
    /** @var list<RuleInterface> */
    private array $rules = [];

    /**
     * @param list<RuleInterface> $rules
     */
    public function __construct(array $rules = [])
    {
        $this->rules = $rules;
    }

    /**
     * Registers an additional rule.
     */
    public function addRule(RuleInterface $rule): self
    {
        $this->rules[] = $rule;
        return $this;
    }

    /**
     * Scans a single PHP file for security issues.
     *
     * @return list<Finding>
     */
    public function scan(string $filePath): array
    {
        if (!is_file($filePath) || !is_readable($filePath)) {
            throw new \InvalidArgumentException(sprintf('File is not readable: %s', $filePath));
        }

        $code = file_get_contents($filePath);
        if ($code === false) {
            throw new \RuntimeException(sprintf('Unable to read file: %s', $filePath));
        }

        $parser = (new ParserFactory())->createForNewestSupportedVersion();

        try {
            $stmts = $parser->parse($code);
            if ($stmts === null) {
                return [];
            }
        } catch (Error $e) {
            // Skip files with parse errors (e.g. incomplete code)
            return [];
        }

        $traverser = new NodeTraverser();
        $visitor = new class($this->rules, $filePath, $code) extends NodeVisitorAbstract {
            /** @var list<Finding> */
            private array $findings = [];
            /** @var list<RuleInterface> */
            private array $rules;
            private string $filePath;
            private string $code;

            public function __construct(array $rules, string $filePath, string $code)
            {
                $this->rules = $rules;
                $this->filePath = $filePath;
                $this->code = $code;
            }

            public function enterNode(Node $node): ?Node
            {
                $context = new Context(
                    file: $this->filePath,
                    source: $this->code,
                    line: $node->getStartLine()
                );

                foreach ($this->rules as $rule) {
                    $finding = $rule->detect($node, $context);
                    if ($finding instanceof Finding) {
                        $this->findings[] = $finding;
                    }
                }

                return null;
            }

            /**
             * @return list<Finding>
             */
            public function getFindings(): array
            {
                return $this->findings;
            }
        };

        $traverser->addVisitor($visitor);
        $traverser->traverse($stmts);

        return $visitor->getFindings();
    }

    /**
     * Recursively scans a directory for all *.php files (skipping vendor).
     *
     * @return list<Finding>
     */
    public function scanDirectory(string $directory): array
    {
        if (!is_dir($directory)) {
            throw new \InvalidArgumentException(sprintf('Directory does not exist: %s', $directory));
        }

        $findings = [];
        $directoryIterator = new \RecursiveDirectoryIterator(
            $directory,
            \RecursiveDirectoryIterator::SKIP_DOTS | \RecursiveDirectoryIterator::FOLLOW_SYMLINKS
        );
        $iterator = new \RecursiveIteratorIterator($directoryIterator);

        foreach ($iterator as $fileInfo) {
            if ($fileInfo->getExtension() !== 'php') {
                continue;
            }

            $realPath = $fileInfo->getRealPath();
            if ($realPath === false) {
                continue;
            }

            // Skip common dependency and test directories
            if (str_contains($realPath, '/vendor/') ||
                str_contains($realPath, '/node_modules/') ||
                str_contains($realPath, '/tests/') ||
                str_contains($realPath, '/.git/')) {
                continue;
            }

            $findings = [...$findings, ...$this->scan($realPath)];
        }

        return $findings;
    }
}
