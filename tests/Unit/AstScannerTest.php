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
 * Uses inline PHP snippets written to temporary files to verify that
 * XssRule, SqlInjectionRule, and MassAssignmentRule correctly identify
 * vulnerable patterns while ignoring safe code. Covers normal cases,
 * edge cases (parse errors, safe equivalents), and error conditions.
 */
final class AstScannerTest extends TestCase
{
    private string $tempDir;

    protected function setUp(): void
    {
        $this->tempDir = sys_get_temp_dir() . '/php_safeguard_test_' . uniqid('', true);
        if (!mkdir($this->tempDir, 0777, true) && !is_dir($this->tempDir)) {
            $this->fail('Failed to create temporary test directory');
        }
    }

    protected function tearDown(): void
    {
        if (is_dir($this->tempDir)) {
            $this->removeDirectory($this->tempDir);
        }
    }

    public function testDetectsXssVulnerability(): void
    {
        $code = <<<'PHP'
<?php
$userInput = $_GET['input'] ?? 'default';
echo $userInput;
print($userInput . '!');
PHP;

        $filePath = $this->createFixtureFile('xss_test.php', $code);
        $scanner = new AstScanner([new XssRule()]);
        $findings = $scanner->scan($filePath);

        $this->assertCount(2, $findings, 'Should detect both echo and print as XSS');
        $this->assertSame('xss', $findings[0]->rule);
        $this->assertSame('xss', $findings[1]->rule);
        $this->assertSame('high', $findings[0]->severity);
        $this->assertStringContainsString('unsanitized data is being output directly', $findings[0]->message);
        $this->assertStringContainsString('echo $userInput', $findings[0]->snippet);
    }

    public function testIgnoresEscapedOutput(): void
    {
        $code = <<<'PHP'
<?php
$userInput = $_GET['input'] ?? '';
echo htmlspecialchars((string) $userInput, ENT_QUOTES);
echo e($userInput); // Laravel helper
print htmlentities($userInput);
PHP;

        $filePath = $this->createFixtureFile('safe_xss.php', $code);
        $scanner = new AstScanner([new XssRule()]);
        $findings = $scanner->scan($filePath);

        $this->assertEmpty($findings, 'Escaping functions should prevent XSS findings');
    }

    public function testDetectsSqlInjection(): void
    {
        $code = <<<'PHP'
<?php
$id = $_GET['id'] ?? 1;
$name = $_POST['name'] ?? '';

DB::raw("SELECT * FROM users WHERE id = " . $id);
DB::query("SELECT * FROM users WHERE name = '" . $name . "'");
PHP;

        $filePath = $this->createFixtureFile('sqli_test.php', $code);
        $scanner = new AstScanner([new SqlInjectionRule()]);
        $findings = $scanner->scan($filePath);

        $this->assertCount(2, $findings, 'Should detect both raw and query with concatenation');
        foreach ($findings as $finding) {
            $this->assertSame('sql-injection', $finding->rule);
            $this->assertSame('critical', $finding->severity);
            $this->assertStringContainsString('Potential SQL injection', $finding->message);
        }
    }

    public function testIgnoresSafeSqlQueries(): void
    {
        $code = <<<'PHP'
<?php
$id = (int) ($_GET['id'] ?? 0);

DB::select("SELECT * FROM users WHERE id = ?", [$id]);
$queryBuilder = DB::table('users')->where('id', $id);
echo $queryBuilder->toSql(); // not a raw sink
PHP;

        $filePath = $this->createFixtureFile('safe_sqli.php', $code);
        $scanner = new AstScanner([new SqlInjectionRule()]);
        $findings = $scanner->scan($filePath);

        $this->assertEmpty($findings, 'Parameterized queries should not trigger SQLi rule');
    }

    public function testDetectsMassAssignment(): void
    {
        $code = <<<'PHP'
<?php
class UserModel {
    public function create(array $data) {}
    public function fill(array $data) {}
}

$requestData = $_POST;
$model = new UserModel();
$model->fill($requestData);
UserModel::create($_POST);
PHP;

        $filePath = $this->createFixtureFile('mass_test.php', $code);
        $scanner = new AstScanner([new MassAssignmentRule()]);
        $findings = $scanner->scan($filePath);

        $this->assertCount(2, $findings);
        $this->assertSame('mass-assignment', $findings[0]->rule);
        $this->assertSame('mass-assignment', $findings[1]->rule);
        $this->assertStringContainsString('Potential mass assignment', $findings[0]->message);
        $this->assertSame('high', $findings[0]->severity);
    }

    public function testScanDirectoryCollectsFindingsFromMultipleFiles(): void
    {
        $this->createFixtureFile('file1.php', <<<'PHP'
<?php
echo $_GET['x'];
PHP);

        $this->createFixtureFile('file2.php', <<<'PHP'
<?php
$id = $_GET['id'];
DB::raw("SELECT * FROM users WHERE id = " . $id);
PHP);

        $scanner = new AstScanner([
            new XssRule(),
            new SqlInjectionRule(),
        ]);
        $findings = $scanner->scanDirectory($this->tempDir);

        $this->assertGreaterThanOrEqual(2, count($findings));

        $rules = array_map(static fn(Finding $f): string => $f->rule, $findings);
        $this->assertContains('xss', $rules);
        $this->assertContains('sql-injection', $rules);
    }

    public function testThrowsExceptionForNonExistentFile(): void
    {
        $scanner = new AstScanner([]);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('File is not readable');

        $scanner->scan('/non/existent/file.php');
    }

    public function testHandlesParseErrorsGracefully(): void
    {
        $code = <<<'PHP'
<?php
this is not valid PHP at all {
PHP;

        $filePath = $this->createFixtureFile('parse_error.php', $code);
        $scanner = new AstScanner([new XssRule(), new SqlInjectionRule()]);
        $findings = $scanner->scan($filePath);

        $this->assertEmpty($findings, 'Parse errors should return empty findings without crashing');
    }

    public function testEmptyRulesProduceNoFindings(): void
    {
        $code = <<<'PHP'
<?php
echo $_GET['danger'];
DB::raw("SELECT * FROM " . $_GET['id']);
PHP;

        $filePath = $this->createFixtureFile('empty_rules.php', $code);
        $scanner = new AstScanner([]);
        $findings = $scanner->scan($filePath);

        $this->assertEmpty($findings);
    }

    /**
     * Creates a temporary PHP fixture file.
     */
    private function createFixtureFile(string $filename, string $content): string
    {
        $path = $this->tempDir . '/' . $filename;
        if (file_put_contents($path, $content) === false) {
            $this->fail(sprintf('Could not write test fixture %s', $filename));
        }
        return $path;
    }

    /**
     * Recursively removes a directory and all its contents.
     */
    private function removeDirectory(string $dir): void
    {
        $items = array_diff(scandir($dir) ?: [], ['.', '..']);
        foreach ($items as $item) {
            $path = $dir . DIRECTORY_SEPARATOR . $item;
            if (is_dir($path)) {
                $this->removeDirectory($path);
            } else {
                unlink($path);
            }
        }
        rmdir($dir);
    }
}
