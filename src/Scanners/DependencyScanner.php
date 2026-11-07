<?php

declare(strict_types=1);

namespace PhpSafeguard\Scanners;

use GuzzleHttp\Client;
use GuzzleHttp\ClientInterface;
use GuzzleHttp\Exception\GuzzleException;
use PhpSafeguard\Reporting\Finding;

/**
 * Audits composer.lock against the GitHub Advisory Database.
 *
 * Queries the GitHub API for known vulnerabilities in Composer packages
 * and reports any that affect the locked versions. Uses CVSS-inspired
 * severity mapping and provides upgrade suggestions.
 */
final class DependencyScanner
{
    private ClientInterface $client;

    public function __construct(?ClientInterface $client = null)
    {
        $this->client = $client ?? new Client([
            'timeout' => 8.0,
            'headers' => [
                'User-Agent' => 'php-safeguard/1.0',
                'Accept' => 'application/vnd.github+json',
            ],
        ]);
    }

    /**
     * Scans composer.lock (if present) and returns vulnerability findings.
     *
     * @return list<Finding>
     */
    public function scan(?string $projectPath = null): array
    {
        $projectPath = $projectPath ?? (string) getcwd();
        $lockFile = $projectPath . '/composer.lock';

        if (!file_exists($lockFile) || !is_readable($lockFile)) {
            return [];
        }

        $lockData = json_decode(file_get_contents($lockFile), true, 512, JSON_THROW_ON_ERROR);
        if (!isset($lockData['packages']) || !is_array($lockData['packages'])) {
            return [];
        }

        $findings = [];

        foreach ($lockData['packages'] as $package) {
            if (!isset($package['name'], $package['version'])) {
                continue;
            }

            $name = (string) $package['name'];
            $version = ltrim((string) $package['version'], 'v');

            $advisories = $this->queryGitHubAdvisories($name);

            foreach ($advisories as $advisory) {
                if (!isset($advisory['vulnerabilities']) || !is_array($advisory['vulnerabilities'])) {
                    continue;
                }

                foreach ($advisory['vulnerabilities'] as $vuln) {
                    if (!isset($vuln['vulnerable_version_range'])) {
                        continue;
                    }

                    if ($this->versionInRange($version, (string) $vuln['vulnerable_version_range'])) {
                        $severity = $this->normalizeSeverity($advisory['severity'] ?? 'medium');

                        $findings[] = new Finding(
                            rule: 'vulnerable-dependency',
                            message: sprintf(
                                '%s %s is vulnerable: %s',
                                $name,
                                $version,
                                $advisory['summary'] ?? 'Unknown vulnerability'
                            ),
                            file: 'composer.lock',
                            line: 1,
                            severity: $severity,
                            snippet: null,
                            suggestion: sprintf(
                                'Update to %s. See GHSA: %s',
                                $advisory['patched_versions'] ?? 'a patched version',
                                $advisory['html_url'] ?? $advisory['ghsa_id'] ?? ''
                            )
                        );
                        break 2; // only report a package once
                    }
                }
            }
        }

        return $findings;
    }

    /**
     * Queries the GitHub Advisory API for a specific Composer package.
     *
     * @return array<array<string, mixed>>
     */
    private function queryGitHubAdvisories(string $packageName): array
    {
        try {
            $response = $this->client->request('GET', 'https://api.github.com/advisories', [
                'query' => [
                    'ecosystem' => 'composer',
                    'package' => $packageName,
                ],
            ]);

            if ($response->getStatusCode() !== 200) {
                return [];
            }

            $data = json_decode((string) $response->getBody(), true, 512, JSON_THROW_ON_ERROR);
            return is_array($data) ? $data : [];
        } catch (GuzzleException | \JsonException) {
            // Network issues or rate limiting should not break the scan
            return [];
        }
    }

    /**
     * Checks whether a version falls inside a vulnerability range.
     */
    private function versionInRange(string $version, string $range): bool
    {
        $range = trim($range);
        if ($range === '') {
            return false;
        }

        // Handle compound ranges (e.g. ">= 1.2.3, < 1.3.0")
        if (str_contains($range, ',')) {
            $parts = array_map('trim', explode(',', $range));
            foreach ($parts as $part) {
                if (!$this->matchesSingleConstraint($version, $part)) {
                    return false;
                }
            }
            return true;
        }

        return $this->matchesSingleConstraint($version, $range);
    }

    /**
     * Evaluates a single version constraint against the installed version.
     */
    private function matchesSingleConstraint(string $version, string $constraint): bool
    {
        $constraint = trim($constraint);

        if (preg_match('/^([<>=!]+)\s*(.+)$/i', $constraint, $matches)) {
            $operator = $matches[1];
            $bound = $matches[2];

            return match ($operator) {
                '<' => version_compare($version, $bound, '<'),
                '<=' => version_compare($version, $bound, '<='),
                '>' => version_compare($version, $bound, '>'),
                '>=' => version_compare($version, $bound, '>='),
                '=' => version_compare($version, $bound, '=='),
                '==' => version_compare($version, $bound, '=='),
                default => false,
            };
        }

        // No operator = exact match
        return version_compare($version, $constraint, '==');
    }

    /**
     * Maps GitHub severity strings to our internal levels.
     */
    private function normalizeSeverity(string $severity): string
    {
        return match (strtolower($severity)) {
            'critical', 'high' => 'critical',
            'moderate' => 'medium',
            'low' => 'low',
            default => 'medium',
        };
    }
}
