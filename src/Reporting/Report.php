<?php

declare(strict_types=1);

namespace PhpSafeguard\Reporting;

use Symfony\Component\Console\Style\SymfonyStyle;

/**
 * Immutable value object representing a security scan report.
 *
 * Aggregates findings and provides formatted output for console, JSON,
 * and SARIF (Static Analysis Results Interchange Format) consumers.
 * The SARIF output is specifically crafted for compatibility with GitHub
 * Advanced Security code scanning.
 */
final class Report
{
    /**
     * @var list<Finding>
     */
    private readonly array $findings;

    /**
     * @var array<string, mixed>
     */
    private readonly array $config;

    /**
     * @param list<Finding> $findings
     * @param array<string, mixed> $config
     */
    public function __construct(array $findings, array $config = [])
    {
        $this->findings = $this->sortFindingsBySeverity($findings);
        $this->config = $config;
    }

    /**
     * Renders findings to the terminal with color-coded severity levels.
     */
    public function toConsole(SymfonyStyle $io): void
    {
        if ($this->findings === []) {
            $io->success('No security issues found.');
            return;
        }

        $io->section(sprintf('Found %d security issue(s)', count($this->findings)));

        foreach ($this->findings as $finding) {
            $this->printFinding($io, $finding);
        }

        $io->newLine();
        $io->text('Run with <info>--fix</info> to apply safe automatic fixes where possible.');
    }

    /**
     * Returns findings as a pretty-printed JSON string.
     */
    public function toJson(): string
    {
        $payload = array_map(
            static fn(Finding $f): array => [
                'rule' => $f->rule,
                'severity' => $f->severity,
                'message' => $f->message,
                'file' => $f->file,
                'line' => $f->line,
                'snippet' => $f->snippet,
                'suggestion' => $f->suggestion,
            ],
            $this->findings
        );

        return json_encode($payload, JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
    }

    /**
     * Returns findings in SARIF 2.1.0 format optimized for GitHub Advanced
     * Security code scanning uploads. Includes rich rule metadata (full
     * description, help, OWASP links, tags), security-severity scores,
     * relative paths with uriBaseId, and per-finding properties.
     */
    public function toSarif(): string
    {
        $results = array_map(function (Finding $finding): array {
            return [
                'ruleId' => 'php-safeguard/' . $finding->rule,
                'level' => $this->mapSeverityToSarifLevel($finding->severity),
                'message' => [
                    'text' => $finding->message,
                ],
                'locations' => [
                    [
                        'physicalLocation' => [
                            'artifactLocation' => [
                                'uri' => $this->makeRelativePath($finding->file),
                                'uriBaseId' => '%SRCROOT%',
                            ],
                            'region' => [
                                'startLine' => $finding->line,
                            ],
                        ],
                    ],
                ],
                'properties' => [
                    'snippet' => $finding->snippet,
                    'suggestion' => $finding->suggestion,
                    'security-severity' => $this->mapSeverityToSecuritySeverity($finding->severity),
                ],
            ];
        }, $this->findings);

        $sarif = [
            'version' => '2.1.0',
            '$schema' => 'https://json.schemastore.org/sarif-2.1.0-rtm.5.json',
            'runs' => [
                [
                    'tool' => [
                        'driver' => [
                            'name' => 'PHP Safeguard',
                            'version' => '1.0.0',
                            'informationUri' => 'https://github.com/php-safeguard/php-safeguard',
                            'rules' => $this->buildSarifRules(),
                        ],
                    ],
                    'results' => $results,
                ],
            ],
        ];

        return json_encode($sarif, JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
    }

    /**
     * Prints a single finding with appropriate coloring and formatting.
     */
    private function printFinding(SymfonyStyle $io, Finding $finding): void
    {
        $severityColor = match (strtolower($finding->severity)) {
            'critical' => 'red',
            'high' => 'bright-red',
            'medium' => 'yellow',
            default => 'blue',
        };

        $io->text(sprintf(
            '<fg=%s;options=bold>[%s] %s</>',
            $severityColor,
            strtoupper($finding->severity),
            $finding->rule
        ));

        $io->text(sprintf('  <info>%s:%d</info>', $finding->file, $finding->line));
        $io->text('  ' . $finding->message);

        if ($finding->snippet !== null && $finding->snippet !== '') {
            $io->text('  <comment>' . $finding->snippet . '</comment>');
        }

        if ($finding->suggestion !== null) {
            $io->text('  <fg=green>Suggestion:</> ' . $finding->suggestion);
        }

        $io->newLine();
    }

    /**
     * Sorts findings by severity (critical first) then by file and line.
     *
     * @param list<Finding> $findings
     * @return list<Finding>
     */
    private function sortFindingsBySeverity(array $findings): array
    {
        $order = ['critical' => 0, 'high' => 1, 'medium' => 2, 'low' => 3];

        usort($findings, static function (Finding $a, Finding $b) use ($order): int {
            $sevA = $order[$a->severity] ?? 4;
            $sevB = $order[$b->severity] ?? 4;

            if ($sevA !== $sevB) {
                return $sevA - $sevB;
            }

            if ($a->file !== $b->file) {
                return $a->file <=> $b->file;
            }

            return $a->line <=> $b->line;
        });

        return $findings;
    }

    /**
     * Maps internal severity levels to SARIF result levels.
     */
    private function mapSeverityToSarifLevel(string $severity): string
    {
        return match (strtolower($severity)) {
            'critical', 'high' => 'error',
            'medium' => 'warning',
            default => 'note',
        };
    }

    /**
     * Converts an absolute filesystem path into a repository-relative URI.
     * Normalizes separators to forward slashes (required by SARIF).
     */
    private function makeRelativePath(string $path): string
    {
        $base = (string) getcwd();
        if (str_starts_with($path, $base . DIRECTORY_SEPARATOR)) {
            $relative = substr($path, strlen($base) + 1);
            return str_replace(DIRECTORY_SEPARATOR, '/', $relative);
        }

        return $path;
    }

    /**
     * Maps internal severity strings to a numeric CVSS-like score that
     * GitHub Advanced Security understands.
     */
    private function mapSeverityToSecuritySeverity(string $severity): float
    {
        return match (strtolower($severity)) {
            'critical' => 9.8,
            'high' => 7.5,
            'medium' => 5.0,
            'low' => 2.0,
            default => 5.0,
        };
    }

    /**
     * Builds rich SARIF rule metadata for every unique rule that produced
     * a finding. Supplies fullDescription, help text, OWASP references,
     * tags and security-severity so that GitHub can display high-quality
     * alerts with contextual guidance.
     *
     * @return list<array<string, mixed>>
     */
    private function buildSarifRules(): array
    {
        $knownRules = [
            'xss' => [
                'id' => 'php-safeguard/xss',
                'name' => 'Cross-Site-Scripting',
                'shortDescription' => [
                    'text' => 'Potential XSS vulnerability',
                ],
                'fullDescription' => [
                    'text' => 'Unsanitized data from user input is output directly to the browser. This can lead to reflected or stored cross-site scripting attacks.',
                ],
                'help' => [
                    'text' => 'Wrap output with htmlspecialchars((string) $var, ENT_QUOTES | ENT_SUBSTITUTE, \'UTF-8\'). Prefer using a templating system with built-in escaping such as Blade.',
                ],
                'helpUri' => 'https://owasp.org/www-community/attacks/xss/',
                'properties' => [
                    'tags' => ['security', 'xss'],
                    'precision' => 'high',
                    'security-severity' => 7.5,
                ],
            ],
            'sql-injection' => [
                'id' => 'php-safeguard/sql-injection',
                'name' => 'SQL-Injection',
                'shortDescription' => [
                    'text' => 'Potential SQL injection',
                ],
                'fullDescription' => [
                    'text' => 'User-controlled data is concatenated into a dynamic SQL query without proper parameterization. This can allow attackers to alter the query logic.',
                ],
                'help' => [
                    'text' => 'Use prepared statements with bound parameters (PDO::prepare, query builder where() with values) instead of string concatenation or DB::raw().',
                ],
                'helpUri' => 'https://owasp.org/www-community/attacks/SQL_Injection',
                'properties' => [
                    'tags' => ['security', 'sql-injection'],
                    'precision' => 'high',
                    'security-severity' => 9.8,
                ],
            ],
            'mass-assignment' => [
                'id' => 'php-safeguard/mass-assignment',
                'name' => 'Mass-Assignment',
                'shortDescription' => [
                    'text' => 'Potential mass assignment',
                ],
                'fullDescription' => [
                    'text' => 'Untrusted request data is passed to model creation or update methods. Attackers may be able to set restricted fields such as role or is_admin.',
                ],
                'help' => [
                    'text' => 'Use Form Requests with validated() or explicitly set $fillable and $guarded properties on Eloquent models. Avoid forceFill() on user input.',
                ],
                'helpUri' => 'https://laravel.com/docs/eloquent#mass-assignment',
                'properties' => [
                    'tags' => ['security', 'laravel', 'mass-assignment'],
                    'precision' => 'medium',
                    'security-severity' => 6.5,
                ],
            ],
            'vulnerable-dependency' => [
                'id' => 'php-safeguard/vulnerable-dependency',
                'name' => 'Vulnerable-Dependency',
                'shortDescription' => [
                    'text' => 'Vulnerable Composer dependency',
                ],
                'fullDescription' => [
                    'text' => 'A package listed in composer.lock has a known vulnerability according to the GitHub Advisory Database.',
                ],
                'help' => [
                    'text' => 'Run composer update on the affected package or use a patched version as indicated in the advisory.',
                ],
                'helpUri' => 'https://github.com/advisories',
                'properties' => [
                    'tags' => ['security', 'dependency'],
                    'precision' => 'high',
                    'security-severity' => 8.0,
                ],
            ],
        ];

        $usedRuleNames = array_unique(array_map(
            static fn(Finding $f): string => $f->rule,
            $this->findings
        ));

        $rules = [];
        foreach ($usedRuleNames as $ruleName) {
            if (isset($knownRules[$ruleName])) {
                $rules[] = $knownRules[$ruleName];
                continue;
            }

            // fallback for any additional rules
            $rules[] = [
                'id' => 'php-safeguard/' . $ruleName,
                'name' => ucwords(str_replace(['-', '_'], ' ', $ruleName)),
                'shortDescription' => [
                    'text' => 'Security issue detected by PHP Safeguard',
                ],
                'helpUri' => 'https://github.com/php-safeguard/php-safeguard',
                'properties' => [
                    'tags' => ['security'],
                    'precision' => 'medium',
                ],
            ];
        }

        return $rules;
    }
}
