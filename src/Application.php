<?php

declare(strict_types=1);

namespace PhpSafeguard;

use PhpSafeguard\Commands\InitCommand;
use PhpSafeguard\Commands\ScanCommand;
use PhpSafeguard\Config\Loader;
use Symfony\Component\Console\Application as SymfonyApplication;

/**
 * Bootstraps the Symfony Console application for PHP Safeguard.
 *
 * Registers all available commands, loads project configuration from
 * .safeguard.yml (or defaults), and prepares the CLI environment.
 */
final class Application extends SymfonyApplication
{
    /**
     * Current version of PHP Safeguard.
     */
    private const VERSION = '1.0.0';

    public function __construct()
    {
        parent::__construct('PHP Safeguard', self::VERSION);

        $this->setCatchExceptions(true);
        $this->setAutoExit(true);

        $configLoader = new Loader();
        $config = $configLoader->load();

        $this->add(new InitCommand());
        $this->add(new ScanCommand($config));

        // Make 'scan' the default command so running `safeguard` without
        // arguments executes a scan (while still allowing `safeguard init`).
        $this->setDefaultCommand('scan');
    }
}
