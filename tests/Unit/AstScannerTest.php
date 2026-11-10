<?php

declare(strict_types=1);

namespace PhpSafeguard\Tests\Unit;

use PhpSafeguard\Reporting\Finding;
use PhpSafeguard\Rules\Laravel\MassAssignmentRule;
use PhpSafeguard\Rules\SecretLeakRule;
use PhpSafeguard\Rules\SqlInjectionRule;
use PhpSafeguard\Rules\XssRule;
use PhpSafeguard\Scanners\AstScanner;
use PHPUnit\Framework\TestCase;

/**
 * Unit tests for the AST scanner and all registered security rules.
 */
final class AstScannerTest extends TestCase
{
    private AstScanner $scanner;

    protected function setUp(): void
    {
        $this->scanner = new AstScanner([
            new XssRule(),
            new SqlInjectionRule(),
            new MassAssignmentRule(),
            new SecretLeakRule(),
        ]);
    }

    public function testDetectsXss(): void
    {
        $code = <<<'PHP'
<?php
echo $userInput;
print $tainted;
PHP;
        $tmpFile = $this->createTempFile($code);
        $findings = $this->scanner->scan($tmpFile);

        $xssFindings = array_filter($findings, static fn(Finding $f): bool => $f->rule === 'xss');
        $this->assertCount(2, $xssFindings);
        $this->assertSame('high', $xssFindings[array_key_first($xssFindings)]->severity);

        unlink($tmpFile);
    }

    public function testDetectsSqlInjection(): void
    {
        $code = <<<'PHP'
<?php
DB::raw("SELECT * FROM users WHERE id = " . $id);
$query->whereRaw('name = "' . $name . '"');
PHP;
        $tmpFile = $this->createTempFile($code);
        $findings = $this->scanner->scan($tmpFile);

        $sqliFindings = array_filter($findings, static fn(Finding $f): bool => $f->rule === 'sql-injection');
        $this->assertCount(2, $sqliFindings);
        $this->assertSame('critical', $sqliFindings[array_key_first($sqliFindings)]->severity);

        unlink($tmpFile);
    }

    public function testDetectsMassAssignment(): void
    {
        $code = <<<'PHP'
<?php
$user->fill($request->all());
Model::create($data);
PHP;
        $tmpFile = $this->createTempFile($code);
        $findings = $this->scanner->scan($tmpFile);

        $massFindings = array_filter($findings, static fn(Finding $f): bool => $f->rule === 'mass-assignment');
        $this->assertCount(2, $massFindings);
        $this->assertSame('high', $massFindings[array_key_first($massFindings)]->severity);

        unlink($tmpFile);
    }

    public function testDetectsSecretLeak(): void
    {
        $code = <<<'PHP'
<?php
$apiKey = 'AKIAIOSFODNN7EXAMPLE123';
$password = 'supersecretpassword123456789';
$config = ['secret' => 'ghp_abcdefghijklmnopqrstuvwxyz1234567890ABCD'];
$safe = 'this-is-just-a-normal-string';
PHP;
        $tmpFile = $this->createTempFile($code);
        $findings = $this->scanner->scan($tmpFile);

        $secretFindings = array_values(array_filter(
            $findings,
            static fn(Finding $f): bool => $f->rule === 'secret-leak'
        ));

        $this->assertCount(3, $secretFindings);
        foreach ($secretFindings as $finding) {
            $this->assertSame('critical', $finding->severity);
            $this->assertStringContainsString('...', $finding->snippet ?? '');
        }

        unlink($tmpFile);
    }

    public function testIgnoresSafeCode(): void
    {
        $code = <<<'PHP'
<?php
echo htmlspecialchars($input);
DB::table('users')->where('id', $id);
$user->fill($validated);
$normalVar = 'just a normal string with low entropy';
$config = ['message' => 'hello world'];
PHP;
        $tmpFile = $this->createTempFile($code);
        $findings = $this->scanner->scan($tmpFile);

        $this->assertCount(0, $findings);

        unlink($tmpFile);
    }

    public function testHandlesParseErrorsGracefully(): void
    {
        $code = '<?php this is not valid PHP code';
        $tmpFile = $this->createTempFile($code);
        $findings = $this->scanner->scan($tmpFile);

        $this->assertCount(0, $findings);

        unlink($tmpFile);
    }

    /**
     * Creates a temporary PHP file for scanning.
     */
    private function createTempFile(string $content): string
    {
        $tmpFile = tempnam(sys_get_temp_dir(), 'php_safeguard_test_');
        if ($tmpFile === false) {
            $this->fail('Could not create temporary file');
        }

        if (file_put_contents($tmpFile, $content) === false) {
            $this->fail('Could not write to temporary file');
        }

        return $tmpFile;
    }
}
