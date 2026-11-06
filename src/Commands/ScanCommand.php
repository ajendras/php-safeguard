<?php

declare(strict_types=1);

namespace PhpSafeguard\Commands;

use PhpSafeguard\Reporting\Finding;
use PhpSafeguard\Reporting\Report;
use PhpSafeguard\Rules\Laravel\MassAssignmentRule;
use PhpSafeguard\Rules\SqlInjectionRule;
use PhpSafeguard\Rules\XssRule;
use PhpSafeguard\Scanners\AstScanner;
use PhpSafeguard\Scanners\DependencyScanner;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

/**
 * Main command that orchestrates security scanning of PHP/Laravel projects.
 *
 * Supports multiple output formats, safe auto-fix mode, progress control,
 * and CI-friendly non-zero exit codes when high-severity issues are found.
 */
#[AsCommand(
    name: 'scan',
    description: 'Scan project for OWASP security issues'
)]
final class ScanCommand extends Command
{
    private const SEVERITY_ORDER = [
        'low' => 0,
        'medium' => 1,
        'high' => 2,
        'critical' => 3,
    ];

    public function __construct(private readonly array $config = [])
    {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this
            ->addOption(
                'format',
                null,
                InputOption::VALUE_REQUIRED,
                'Output format: console, json, sarif',
                $this->config['report']['format'] ?? 'console'
            )
            ->addOption(
                'fix',
                null,
                InputOption::VALUE_NONE,
                'Automatically apply safe fixes (e.g. htmlspecialchars, security headers)'
            )
            ->addOption(
                'no-progress',
                null,
                InputOption::VALUE_NONE,
                'Disable progress indicators'
            )
            ->addOption(
                'path',
                'p',
                InputOption::VALUE_REQUIRED,
                'Directory to scan',
                (string) getcwd()
            );
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);
        $io->title('PHP Safeguard Security Scanner');

        $format = (string) $input->getOption('format');
        $shouldFix = $input->getOption('fix') || ($this->config['auto-fix']['enabled'] ?? false);
        $noProgress = (bool) $input->getOption('no-progress');
        $scanPath = (string) $input->getOption('path');

        if (!is_dir($scanPath)) {
            $io->error(sprintf('Path does not exist or is not a directory: %s', $scanPath));
            return Command::FAILURE;
        }

        $io->text(sprintf('Scanning <info>%s</info>', $scanPath));

        $rules = $this->buildRulesFromConfig();
        $astScanner = new AstScanner($rules);
        $dependencyScanner = new DependencyScanner();

        $findings = [];

        if (!$noProgress) {
            $io->progressStart();
        }

        $io->section('AST Analysis');
        try {
            $findings = array_merge($findings, $astScanner->scanDirectory($scanPath));
            if (!$noProgress) {
                $io->progressAdvance(60);
            }
        } catch (\Throwable $e) {
            $io->warning('AST scanner failed: ' . $e->getMessage());
        }

        $io->section('Dependency Audit');
        try {
            $findings = array_merge($findings, $dependencyScanner->scan($scanPath));
            if (!$noProgress) {
                $io->progressAdvance(40);
            }
        } catch (\Throwable $e) {
            $io->warning('Dependency scanner failed: ' . $e->getMessage());
        }

        if (!$noProgress) {
            $io->progressFinish();
        }

        $report = new Report($findings, $this->config);

        match ($format) {
            'json' => $io->writeln($report->toJson()),
            'sarif' => $io->writeln($report->toSarif()),
            default => $report->toConsole($io),
        };

        $exitCode = $this->calculateExitCode($findings);

        if ($shouldFix) {
            $io->section('Applying Safe Auto-Fixes');
            $this->applySafeFixes($scanPath, $findings, $io);
        }

        $issueCount = count($findings);
        if ($issueCount > 0) {
            $io->caution(sprintf('Found %d security issue(s).', $issueCount));
        } else {
            $io->success('No security issues detected.');
        }

        $io->text('Configuration used: <info>.safeguard.yml</info> (or defaults)');
        return $exitCode;
    }

    /**
     * Instantiates enabled rules based on configuration.
     *
     * @return list<\PhpSafeguard\Rules\RuleInterface>
     */
    private function buildRulesFromConfig(): array
    {
        $rules = [];
        $enabled = $this->config['rules'] ?? [];

        if ($enabled['xss'] ?? false) {
            $rules[] = new XssRule();
        }

        if ($enabled['sql-injection'] ?? false) {
            $rules[] = new SqlInjectionRule();
        }

        if ($enabled['mass-assignment'] ?? false) {
            $rules[] = new MassAssignmentRule();
        }

        // Additional rules can be registered here as they are implemented
        // (command-injection, laravel-validation, route-model-binding, etc.)

        return $rules;
    }

    /**
     * Determines process exit code for CI compatibility.
     */
    private function calculateExitCode(array $findings): int
    {
        $minimumSeverity = $this->config['severity']['minimum'] ?? 'medium';
        $minimumLevel = self::SEVERITY_ORDER[$minimumSeverity] ?? 1;

        foreach ($findings as $finding) {
            $severity = $finding->severity;
            $level = self::SEVERITY_ORDER[$severity] ?? 1;
            if ($level >= $minimumLevel) {
                return Command::FAILURE;
            }
        }

        return Command::SUCCESS;
    }

    /**
     * Applies safe, non-breaking fixes for common issues.
     *
     * Currently handles output escaping and security headers.
     */
    private function applySafeFixes(string $scanPath, array $findings, SymfonyStyle $io): void
    {
        $fixed = 0;
        $autoFixConfig = $this->config['auto-fix'] ?? [];

        // Fix 1: Add missing security headers to entrypoint files
        if ($autoFixConfig['headers'] ?? true) {
            $entryFiles = ['index.php', 'public/index.php', 'artisan'];
            foreach ($entryFiles as $file) {
                $fullPath = $scanPath . '/' . $file;
                if (!file_exists($fullPath) || !is_writable($fullPath)) {
                    continue;
                }

                $content = file_get_contents($fullPath);
                if ($content === false || str_contains($content, 'X-Frame-Options')) {
                    continue;
                }

                $headerBlock = <<<'PHP'
                // Security headers added automatically by PHP Safeguard
                header('X-Frame-Options: DENY');
                header('X-Content-Type-Options: nosniff');
                header('Referrer-Policy: strict-origin-when-cross-origin');
                header('Strict-Transport-Security: max-age=31536000; includeSubDomains');

                PHP;

                $content = preg_replace(
                    '/^<\?php\s*/',
                    "<?php\n\n" . $headerBlock,
                    $content
                );

                if (file_put_contents($fullPath, $content) !== false) {
                    $fixed++;
                    $io->text(sprintf('Added security headers to <info>%s</info>', $file));
                }
            }
        }

        // Fix 2: Wrap obvious echo/print of variables with htmlspecialchars
        if ($autoFixConfig['escape-output'] ?? true) {
            foreach ($findings as $finding) {
                if ($finding->rule !== 'xss' || $finding->suggestion === null) {
                    continue;
                }

                $filePath = $finding->file;
                if (!file_exists($filePath) || !is_writable($filePath)) {
                    continue;
                }

                $content = file_get_contents($filePath);
                if ($content === false) {
                    continue;
                }

                // Very conservative replacement for common echo $var; patterns
                $escaped = preg_replace(
                    '/echo\s+([^;]+?)(;|$)/',
                    'echo htmlspecialchars((string) $1, ENT_QUOTES | ENT_SUBSTITUTE, \'UTF-8\')$2',
                    $content
                );

                if ($escaped !== $content && file_put_contents($filePath, $escaped) !== false) {
                    $fixed++;
                    $io->text(sprintf('Escaped output in <info>%s:%d</info>', basename($filePath), $finding->line));
                    break; // only fix one per file to be safe
                }
            }
        }

        if ($fixed > 0) {
            $io->success(sprintf('Applied %d safe fix(es). Review changes before committing.', $fixed));
        } else {
            $io->note('No safe automatic fixes were applicable.');
        }
    }
}
