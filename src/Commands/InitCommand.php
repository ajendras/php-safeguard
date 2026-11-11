<?php

declare(strict_types=1);

namespace PhpSafeguard\Commands;

use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;
use Symfony\Component\Yaml\Yaml;

/**
 * Initializes a new .safeguard.yml configuration file in the current project.
 *
 * Detects Laravel projects automatically and enables appropriate rules.
 * Uses SymfonyStyle for rich terminal UX with colors and clear messaging.
 */
#[AsCommand(
    name: 'init',
    description: 'Create a new .safeguard.yml file with sensible defaults'
)]
final class InitCommand extends Command
{
    private const CONFIG_FILENAME = '.safeguard.yml';

    protected function configure(): void
    {
        $this
            ->addOption(
                'force',
                'f',
                InputOption::VALUE_NONE,
                'Overwrite the configuration file if it already exists'
            );
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);
        $io->title('PHP Safeguard Initializer');

        $projectPath = (string) getcwd();
        $configPath = $projectPath . '/' . self::CONFIG_FILENAME;

        if (file_exists($configPath) && !$input->getOption('force')) {
            $io->error([
                'Configuration file already exists.',
                'Use <info>--force</info> to overwrite it.',
            ]);

            return Command::FAILURE;
        }

        $isLaravel = $this->detectLaravelProject($projectPath);
        $config = $this->buildDefaultConfig($isLaravel);

        try {
            $yamlContent = Yaml::dump($config, 4, 2, Yaml::DUMP_MULTI_LINE_LITERAL_BLOCK);
            if (file_put_contents($configPath, $yamlContent) === false) {
                throw new \RuntimeException('Unable to write configuration file.');
            }
        } catch (\Throwable $e) {
            $io->error('Failed to create configuration: ' . $e->getMessage());

            return Command::FAILURE;
        }

        $io->success('Configuration file created successfully at ' . self::CONFIG_FILENAME);

        $io->section('Detected Project Type');
        if ($isLaravel) {
            $io->note('Laravel project detected - framework-specific rules have been enabled.');
        } else {
            $io->text('Standard PHP project detected.');
        }

        $io->section('Enabled Rules');
        $enabledRules = array_keys(array_filter($config['rules']));
        $io->listing($enabledRules);

        $io->text([
            '',
            'Next steps:',
            '  <info>safeguard scan</info>          Run a security scan',
            '  <info>safeguard scan --fix</info>    Automatically apply safe fixes',
            '',
            'Customize rules and thresholds by editing <info>.safeguard.yml</info>',
        ]);

        return Command::SUCCESS;
    }

    /**
     * Detects whether the current project is a Laravel application.
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

        $composerContent = file_get_contents($composerPath);
        if ($composerContent === false) {
            return false;
        }

        $composer = json_decode($composerContent, true);

        return isset($composer['require']['laravel/framework'])
            || isset($composer['require-dev']['laravel/framework']);
    }

    /**
     * Returns a sensible default configuration.
     *
     * @return array<string, mixed>
     */
    private function buildDefaultConfig(bool $isLaravel): array
    {
        return [
            'version' => '1.0',
            'rules' => [
                'xss' => true,
                'sql-injection' => true,
                'command-injection' => true,
                'mass-assignment' => $isLaravel,
                'laravel-validation' => $isLaravel,
                'route-model-binding' => $isLaravel,
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
    }
}
