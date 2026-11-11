<?php

declare(strict_types=1);

namespace PhpSafeguard\Tests\Unit;

use PhpParser\Error;
use PhpParser\Node;
use PhpParser\NodeTraverser;
use PhpParser\NodeVisitorAbstract;
use PhpParser\ParserFactory;
use PHPUnit\Framework\TestCase;
use PhpSafeguard\Context;
use PhpSafeguard\Reporting\Finding;
use PhpSafeguard\Rules\Laravel\MassAssignmentRule;
use PhpSafeguard\Rules\RuleInterface;
use PhpSafeguard\Rules\SecretLeakRule;
use PhpSafeguard\Rules\SqlInjectionRule;
use PhpSafeguard\Rules\XssRule;
use PhpSafeguard\Scanners\AstScanner;

final class AstScannerTest extends TestCase
{
    /**
     * @dataProvider provideVulnerableCode
     */
    public function testDetectsVulnerabilities(string $ruleName, string $code, string $expectedMessagePart): void
    {
        $rules = $this->getRulesForName($ruleName);
        $findings = $this->scanCode($code, $rules);

        $this->assertCount(1, $findings);
        $this->assertSame($ruleName, $findings[0]->rule);
        $this->assertStringContainsString($expectedMessagePart, strtolower($findings[0]->message));
    }

    public function provideVulnerableCode(): iterable
    {
        yield 'xss' => [
            'xss',
            '<?php echo $_GET["input"];',
            'xss',
        ];

        yield 'sql-injection' => [
            'sql-injection',
            '<?php DB::raw("SELECT * FROM users WHERE id = " . $id);',
            'sql injection',
        ];

        yield 'mass-assignment' => [
            'mass-assignment',
            '<?php $user->fill($request->all());',
            'mass assignment',
        ];

        yield 'secret-leak' => [
            'secret-leak',
            '<?php $apiKey = "sk_live_1234567890abcdef123456";',
            'secret leak',
        ];
    }

    public function testDoesNotTriggerOnSafeCode(): void
    {
        $code = <<<'PHP'
<?php
echo htmlspecialchars($input, ENT_QUOTES);
DB::select("SELECT * FROM users WHERE id = ?", [$id]);
$user->fill($request->validated());
$safe = 'this-is-a-normal-string-without-high-entropy-or-patterns';
PHP;

        $rules = [
            new XssRule(),
            new SqlInjectionRule(),
            new MassAssignmentRule(),
            new SecretLeakRule(),
        ];

        $findings = $this->scanCode($code, $rules);
        $this->assertEmpty($findings);
    }

    public function testSecretLeakRuleSkipsRegexPatternsAndText(): void
    {
        $code = <<<'PHP'
<?php

private const SECRET_REGEXES = [
    '/AKIA[0-9A-Z]{16,}/',
    '/sk_live_[0-9a-zA-Z]{20,}/',
    '/ghp_[0-9a-zA-Z]{36,}/',
    '/^eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}$/',
];

$description = 'Unsanitized data from user input is output directly to the browser. This can lead to reflected or stored cross-site scripting attacks.';
PHP;

        $rule = new SecretLeakRule();
        $findings = $this->scanCode($code, [$rule]);

        $this->assertEmpty(
            $findings,
            'Regex patterns from the rule itself and descriptive text should not trigger secret-leak'
        );
    }

    public function testHandlesParseErrorsGracefully(): void
    {
        $code = '<?php this is not valid PHP syntax {{{';
        $rules = [new XssRule(), new SecretLeakRule()];

        $findings = $this->scanCode($code, $rules);
        $this->assertEmpty($findings);
    }

    public function testFullScannerPipelineWithDirectory(): void
    {
        $tempDir = sys_get_temp_dir() . '/php-safeguard-test-' . uniqid('', true);
        mkdir($tempDir, 0777, true);

        $testFile = $tempDir . '/vulnerable.php';
        file_put_contents($testFile, <<<'PHP'
<?php
echo $_GET['unsanitized'];
DB::raw('SELECT * FROM users WHERE id='.$id);
$user = new User();
$user->fill($request->all());
$token = 'sk_live_abc123def456ghi789';
PHP);

        try {
            $rules = [
                new XssRule(),
                new SqlInjectionRule(),
                new MassAssignmentRule(),
                new SecretLeakRule(),
            ];

            $scanner = new AstScanner($rules);
            $findings = $scanner->scanDirectory($tempDir);

            $this->assertGreaterThanOrEqual(4, count($findings));

            $ruleNames = array_map(static fn(Finding $f): string => $f->rule, $findings);
            $this->assertContains('xss', $ruleNames);
            $this->assertContains('sql-injection', $ruleNames);
            $this->assertContains('mass-assignment', $ruleNames);
            $this->assertContains('secret-leak', $ruleNames);
        } finally {
            if (file_exists($testFile)) {
                unlink($testFile);
            }
            if (is_dir($tempDir)) {
                rmdir($tempDir);
            }
        }
    }

    /**
     * @param list<RuleInterface> $rules
     * @return list<Finding>
     */
    private function scanCode(string $code, array $rules): array
    {
        $parser = (new ParserFactory())->createForNewestSupportedVersion();

        try {
            $stmts = $parser->parse($code);
        } catch (Error $e) {
            return [];
        }

        $findings = [];
        $traverser = new NodeTraverser();

        $visitor = new class($rules, $findings, $code) extends NodeVisitorAbstract {
            /**
             * @param list<RuleInterface> $rules
             * @param list<Finding> $findings
             */
            public function __construct(
                private readonly array $rules,
                private array &$findings,
                private readonly string $source,
            ) {
            }

            public function enterNode(Node $node): void
            {
                $ctx = new Context(
                    '/tmp/test.php',
                    $this->source,
                    $node->getStartLine() ?? 1,
                );

                foreach ($this->rules as $rule) {
                    $finding = $rule->detect($node, $ctx);
                    if ($finding !== null) {
                        $this->findings[] = $finding;
                    }
                }
            }
        };

        $traverser->addVisitor($visitor);
        $traverser->traverse($stmts ?? []);

        return $findings;
    }

    /**
     * @return list<RuleInterface>
     */
    private function getRulesForName(string $ruleName): array
    {
        return match ($ruleName) {
            'xss' => [new XssRule()],
            'sql-injection' => [new SqlInjectionRule()],
            'mass-assignment' => [new MassAssignmentRule()],
            'secret-leak' => [new SecretLeakRule()],
            default => [],
        };
    }
}
