<?php

declare(strict_types=1);

namespace PhpSafeguard\Tests\Unit;

use PHPUnit\Framework\TestCase;
use PhpSafeguard\Reporting\Finding;
use PhpSafeguard\Rules\Laravel\MassAssignmentRule;
use PhpSafeguard\Rules\SqlInjectionRule;
use PhpSafeguard\Rules\XssRule;
use PhpSafeguard\Scanners\AstScanner;

/**
 * Unit tests for the AST-based security scanner.
 *
 * Covers rule detection for XSS, SQL injection, and mass assignment using
 * temporary fixtures, safe variants, parse errors, and directory scanning
 * with skip logic for vendor/tests directories. Updated for strict PHPUnit 11
 * compatibility and PHP 8.3 runtime behavior.
 */
final class AstScannerTest extends TestCase
{
    private string $tempDir;

    protected function setUp(): void
    {
        $this->tempDir = sys_get_temp_dir() . '/php-safeguard-test-' . bin2hex(random_bytes(8));
        mkdir($this->tempDir, 0777, true);
    }

    protected function tearDown(): void
    {
        if (is_dir($this->tempDir)) {
            $this->removeDirectory($this->tempDir);
        }
    }

    private function removeDirectory(string $directory): void
    {
        $files = scandir($directory);
        if ($files === false) {
            return;
        }

        foreach ($files as $file) {
            if ($file === '.' || $file === '..') {
                continue;
            }

            $path = $directory . DIRECTORY_SEPARATOR . $file;
            if (is_dir($path)) {
                $this->removeDirectory($path);
            } else {
                unlink($path);
            }
        }

        rmdir($directory);
    }

    private function createFixture(string $code, string $filename = 'test.php'): string
    {
        $path = $this->tempDir . '/' . $filename;
        $dir = dirname($path);

        if (!is_dir($dir)) {
            mkdir($dir, 0777, true);
        }

        file_put_contents($path, $code);
        return $path;
    }

    public function testDetectsXssVulnerability(): void
    {
        $code = "<?php\necho \$_GET['user_input'];";
        $filePath = $this->createFixture($code);

        $scanner = new AstScanner([new XssRule()]);
        $findings = $scanner->scan($filePath);

        self::assertCount(1, $findings);
        $finding = $findings[0];

        self::assertInstanceOf(Finding::class, $finding);
        self::assertSame('xss', $finding->rule);
        self::assertSame('high', $finding->severity);
        self::assertSame($filePath, $finding->file);
        self::assertSame(2, $finding->line);
        self::assertStringContainsString('echo', $finding->snippet ?? '');
        self::assertStringContainsString('htmlspecialchars', $finding->suggestion ?? '');
    }

    public function testIgnoresSafeOutputEscaping(): void
    {
        $code = "<?php\necho htmlspecialchars(\$input);";
        $filePath = $this->createFixture($code);

        $scanner = new AstScanner([new XssRule()]);
        $findings = $scanner->scan($filePath);

        self::assertCount(0, $findings);
    }

    public function testDetectsSqlInjection(): void
    {
        $code = "<?php\nDB::raw('SELECT * FROM users WHERE id = ' . \$_GET['id']);";
        $filePath = $this->createFixture($code);

        $scanner = new AstScanner([new SqlInjectionRule()]);
        $findings = $scanner->scan($filePath);

        self::assertCount(1, $findings);
        $finding = $findings[0];

        self::assertInstanceOf(Finding::class, $finding);
        self::assertSame('sql-injection', $finding->rule);
        self::assertSame('critical', $finding->severity);
        self::assertStringContainsString('DB::raw', $finding->snippet ?? '');
        self::assertStringContainsString('prepared statements', $finding->suggestion ?? '');
    }

    public function testIgnoresSafeSqlQuery(): void
    {
        $code = "<?php\nDB::select('SELECT * FROM users WHERE id = ?', [\$id]);";
        $filePath = $this->createFixture($code);

        $scanner = new AstScanner([new SqlInjectionRule()]);
        $findings = $scanner->scan($filePath);

        self::assertCount(0, $findings);
    }

    public function testDetectsMassAssignment(): void
    {
        $code = "<?php\n\$user->fill(\$request->all());";
        $filePath = $this->createFixture($code);

        $scanner = new AstScanner([new MassAssignmentRule()]);
        $findings = $scanner->scan($filePath);

        self::assertCount(1, $findings);
        $finding = $findings[0];

        self::assertInstanceOf(Finding::class, $finding);
        self::assertSame('mass-assignment', $finding->rule);
        self::assertSame('high', $finding->severity);
        self::assertStringContainsString('fill', $finding->snippet ?? '');
        self::assertStringContainsString('$fillable', $finding->suggestion ?? '');
    }

    public function testParseErrorIsSkipped(): void
    {
        $code = "<?php\nthis is invalid php code echo \$var;";
        $filePath = $this->createFixture($code);

        $scanner = new AstScanner([new XssRule(), new SqlInjectionRule()]);
        $findings = $scanner->scan($filePath);

        self::assertCount(0, $findings);
    }

    public function testScanDirectorySkipsVendorAndTests(): void
    {
        $this->createFixture("<?php echo \$_GET['bad'];", 'vendor/bad.php');
        $this->createFixture("<?php echo \$_GET['bad'];", 'tests/bad.php');
        $goodPath = $this->createFixture("<?php echo \$_GET['bad'];", 'good.php');

        $scanner = new AstScanner([new XssRule()]);
        $findings = $scanner->scanDirectory($this->tempDir);

        self::assertCount(1, $findings);
        self::assertStringContainsString('good.php', $findings[0]->file);
    }

    public function testAddRuleDynamically(): void
    {
        $scanner = new AstScanner();
        $scanner->addRule(new XssRule());

        $code = "<?php\necho \$_GET['x'];";
        $filePath = $this->createFixture($code);
        $findings = $scanner->scan($filePath);

        self::assertCount(1, $findings);
    }
}
