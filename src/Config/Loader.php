<?php

declare(strict_types=1);

namespace PhpSafeguard\Config;

use Symfony\Component\Yaml\Exception\ParseException;
use Symfony\Component\Yaml\Yaml;

/**
 * Loads and validates project configuration from .safeguard.yml.
 *
 * Falls back to sensible defaults when no configuration file is present.
 * Performs basic validation on severity thresholds and rule structure.
 */
final class Loader
{
    /**
     * Default configuration used when .safeguard.yml is absent.
     *
     * @var array<string, mixed>
     */
    private const DEFAULT_CONFIG = [
        'version' => '1.0',
        'rules' => [
            'xss' => true,
            'sql-injection' => true,
            'command-injection' => true,
            'mass-assignment' => false,
            'laravel-validation' => false,
            'route-model-binding' => false,
            'secret-leak' => true,
        ],
        'severity' => [
            'minimum' => 'medium',
        ],
        'auto-fix' => [
            'enabled' => true,
            'headers' => true,
            'escape-output' => true,
            'prepared-statements' => true,
            'validation-rules' => true,
        ],
        'ignore' => [],
        'report' => [
            'format' => 'console',
            'show-snippets' => true,
        ],
    ];

    /**
     * Loads configuration, merging user settings with defaults.
     *
     * @return array<string, mixed>
     */
    public function load(?string $projectPath = null): array
    {
        $projectPath = $projectPath ?? (string) getcwd();
        $configPath = $projectPath . '/.safeguard.yml';

        if (!file_exists($configPath)) {
            // Auto-detect Laravel for better defaults when no config file exists
            $defaults = $this->buildDefaultConfig($this->detectLaravelProject($projectPath));
            return $defaults;
        }

        try {
            $yaml = file_get_contents($configPath);
            if ($yaml === false) {
                throw new \RuntimeException('Could not read .safeguard.yml');
            }

            $userConfig = Yaml::parse($yaml);

            if (!is_array($userConfig)) {
                throw new \RuntimeException('.safeguard.yml must contain a YAML mapping (array)');
            }

            $config = $this->merge($this->buildDefaultConfig($this->detectLaravelProject($projectPath)), $userConfig);
            $this->validate($config);

            return $config;
        } catch (ParseException $e) {
            throw new \RuntimeException('YAML syntax error in .safeguard.yml: ' . $e->getMessage(), 0, $e);
        } catch (\Throwable $e) {
            throw new \RuntimeException('Failed to load configuration: ' . $e->getMessage(), 0, $e);
        }
    }

    /**
     * Merges user configuration over defaults (recursive for nested arrays).
     *
     * @param array<string, mixed> $defaults
     * @param array<string, mixed> $user
     * @return array<string, mixed>
     */
    private function merge(array $defaults, array $user): array
    {
        foreach ($user as $key => $value) {
            if (is_array($value) && isset($defaults[$key]) && is_array($defaults[$key])) {
                $defaults[$key] = $this->merge($defaults[$key], $value);
            } else {
                $defaults[$key] = $value;
            }
        }

        return $defaults;
    }

    /**
     * Validates configuration values and throws descriptive exceptions.
     *
     * @param array<string, mixed> $config
     */
    private function validate(array $config): void
    {
        $validSeverities = ['low', 'medium', 'high', 'critical'];

        if (!isset($config['severity']['minimum']) || !is_string($config['severity']['minimum'])) {
            throw new \InvalidArgumentException(
                'severity.minimum must be a string. Valid values: ' . implode(', ', $validSeverities)
            );
        }

        $minimum = $config['severity']['minimum'];
        if (!in_array($minimum, $validSeverities, true)) {
            throw new \InvalidArgumentException(sprintf(
                "Invalid severity.minimum '%s'. Must be one of: %s.",
                $minimum,
                implode(', ', $validSeverities)
            ));
        }

        if (!isset($config['rules']) || !is_array($config['rules'])) {
            throw new \InvalidArgumentException('The "rules" key must be a mapping of rule names to booleans.');
        }

        foreach ($config['rules'] as $rule => $enabled) {
            if (!is_bool($enabled)) {
                throw new \InvalidArgumentException(sprintf(
                    'Rule "%s" must be a boolean (true/false), got %s.',
                    $rule,
                    get_debug_type($enabled)
                ));
            }
        }
    }

    /**
     * Detects whether the current project appears to be a Laravel application.
     */
    private function detectLaravelProject(string $projectPath): bool
    {
        if (file_exists($projectPath . '/artisan')) {
            return true;
        }

        $composerPath = $projectPath . '/composer.json';
        if (!file_exists($composerPath)) {
            return false;
        }

        $content = file_get_contents($composerPath);
        if ($content === false) {
            return false;
        }

        $composer = json_decode($content, true, 512, JSON_THROW_ON_ERROR);

        return isset($composer['require']['laravel/framework'])
            || isset($composer['require-dev']['laravel/framework']);
    }

    /**
     * Builds a default configuration, enabling Laravel rules when appropriate.
     *
     * @return array<string, mixed>
     */
    private function buildDefaultConfig(bool $isLaravel): array
    {
        $config = self::DEFAULT_CONFIG;
        $config['rules']['mass-assignment'] = $isLaravel;
        $config['rules']['laravel-validation'] = $isLaravel;
        $config['rules']['route-model-binding'] = $isLaravel;

        return $config;
    }
}
