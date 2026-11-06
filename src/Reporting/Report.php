<?php

declare(strict_types=1);

namespace PhpSafeguard\Reporting;

use Symfony\Component\Console\Style\SymfonyStyle;

/**
 * Immutable value object representing a security scan report.
 *
 * Aggregates findings and provides formatted output for console, JSON,
 * and SARIF (Static Analysis Results Interchange Format) consumers.
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
     * Returns findings in SARIF 2.1.0 format for integration with GitHub,
     * VS Code, and other analysis platforms.
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
                                'uri' => $finding->file,
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
     * Builds minimal rule metadata for SARIF output.
     *
     * @return list<array<string, mixed>>
     */
    private function buildSarifRules(): array
    {
        $rules = [];
        $uniqueRules = array_unique(array_map(static fn(Finding $f): string => $f->rule, $this->findings));

        foreach ($uniqueRules as $rule) {
            $rules[] = [
                'id' => 'php-safeguard/' . $rule,
                'name' => ucwords(str_replace('-', ' ', $rule)),
                'shortDescription' => [
                    'text' => 'OWASP-related security issue detected by PHP Safeguard',
                ],
                'helpUri' => 'https://github.com/php-safeguard/php-safeguard',
            ];
        }

        return $rules;
    }
}
