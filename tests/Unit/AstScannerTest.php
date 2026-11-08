<?php

declare(strict_types=1);

namespace PhpSafeguard\Tests\Unit;

use PHPUnit\Framework\TestCase;
use PhpSafeguard\Reporting\Finding;
use PhpSafeguard\Rules\Laravel\MassAssignmentRule;
use PhpSafeguard\Rules\SqlInjectionRule;
use PhpSafeguard\Rules\XssRule;
use PhpSafeguard\Scanners\AstScanner;

final class AstScannerTest extends TestCase
{
    private AstScanner $scanner;

    protected function setUp(): void
    {
        $this->scanner = new AstScanner([
            new XssRule(),
            new SqlInjectionRule(),
            new MassAssignmentRule(),
        ]);
    }

    public function testItDetectsXss(): void
    {
        $code = '<?php echo $userInput; ?>';
        $file = $this->createTempFile($code);

        $findings = $this->scanner->scan($file);

        $this->assertCount(1, $findings);
        $finding = $findings[0];
        $this->assertSame('xss', $finding->rule);
        $this->assertSame('high', $finding->severity);
        $this->assertStringContainsString('unsanitized', $finding->message);
        $this->assertSame($file, $finding->file);
        $this->assertGreaterThan(0, $finding->line);
        $this->assertNotNull($finding->snippet);
        $this->assertNotNull($finding->suggestion);

        unlink($file);
    }

    public function testItDoesNotFlagEscapedOutput(): void
    {
        $code = '<?php echo htmlspecialchars($userInput); ?>';
        $file = $this->createTempFile($code);

        $findings = $this->scanner->scan($file);

        $this->assertCount(0, $findings);

        unlink($file);
    }

    public function testItDoesNotFlagLiteralOutput(): void
    {
        $code = '<?php echo "hello"; echo 42; echo 3.14; ?>';
        $file = $this->createTempFile($code);

        $findings = $this->scanner->scan($file);

        $this->assertCount(0, $findings);

        unlink($file);
    }

    public function testItDetectsSqlInjection(): void
    {
        $code = '<?php DB::raw("SELECT * FROM users WHERE id = " . $id);';
        $file = $this->createTempFile($code);

        $findings = $this->scanner->scan($file);

        $this->assertCount(1, $findings);
        $finding = $findings[0];
        $this->assertSame('sql-injection', $finding->rule);
        $this->assertSame('critical', $finding->severity);
        $this->assertStringContainsString('SQL injection', $finding->message);
        $this->assertNotNull($finding->suggestion);

        unlink($file);
    }

    public function testItDoesNotFlagParameterizedQuery(): void
    {
        $code = '<?php DB::select("SELECT * FROM users WHERE id = ?", [$id]);';
        $file = $this->createTempFile($code);

        $findings = $this->scanner->scan($file);

        $this->assertCount(0, $findings);

        unlink($file);
    }

    public function testItDetectsMassAssignment(): void
    {
        $code = '<?php $user->fill($request->all());';
        $file = $this->createTempFile($code);

        $findings = $this->scanner->scan($file);

        $this->assertCount(1, $findings);
        $finding = $findings[0];
        $this->assertSame('mass-assignment', $finding->rule);
        $this->assertSame('high', $finding->severity);
        $this->assertStringContainsString('mass assignment', $finding->message);
        $this->assertNotNull($finding->suggestion);

        unlink($file);
    }

    public function testItHandlesParseErrorsGracefully(): void
    {
        $code = '<?php echo $var';
        $file = $this->createTempFile($code);

        $findings = $this->scanner->scan($file);

        $this->assertCount(0, $findings);

        unlink($file);
    }

    public function testScanDirectorySkipsVendorAndTests(): void
    {
        $tempDir = sys_get_temp_dir() . '/astscanner_test_' . uniqid('', true);
        mkdir($tempDir, 0755, true);

        $vulnerableFile = $tempDir . '/vulnerable.php';
        $code = '<?php echo $_GET["x"]; ?>';
        file_put_contents($vulnerableFile, $code);

        $vendorDir = $tempDir . '/vendor';
        mkdir($vendorDir, 0755, true);
        $vendorFile = $vendorDir . '/lib.php';
        file_put_contents($vendorFile, '<?php echo $tainted; ?>');

        $testSubDir = $tempDir . '/tests';
        mkdir($testSubDir, 0755, true);
        $testFile = $testSubDir . '/test.php';
        file_put_contents($testFile, '<?php echo $unsafe; ?>');

        $findings = $this->scanner->scanDirectory($tempDir);

        $this->assertCount(1, $findings);
        $this->assertStringContainsString('vulnerable.php', $findings[0]->file);
        $this->assertStringNotContainsString('vendor', $findings[0]->file);
        $this->assertStringNotContainsString('/tests/', $findings[0]->file);

        $this->recursiveRemoveDir($tempDir);
    }

    private function createTempFile(string $content): string
    {
        $file = tempnam(sys_get_temp_dir(), 'php_safeguard_test_');
        if ($file === false) {
            throw new \RuntimeException('Failed to create temp file');
        }
        file_put_contents($file, $content);
        return $file;
    }

    private function recursiveRemoveDir(string $dir): void
    {
        $files = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($dir, \RecursiveDirectoryIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::CHILD_FIRST
        );

        foreach ($files as $fileInfo) {
            $todo = ($fileInfo->isDir() ? 'rmdir' : 'unlink');
            $todo($fileInfo->getRealPath());
        }

        rmdir($dir);
    }
}
