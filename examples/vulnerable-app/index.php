<?php

declare(strict_types=1);

/**
 * Vulnerable demo application for PHP Safeguard.
 *
 * This file intentionally contains several OWASP-related security issues
 * that the scanner (XssRule, SqlInjectionRule, MassAssignmentRule) will detect.
 *
 * Run the scanner with:
 *     safeguard scan examples/vulnerable-app
 *
 * Or run the demo server with:
 *     php -S localhost:8080 -t examples/vulnerable-app
 */

header('Content-Type: text/html; charset=utf-8');

// Dummy definitions so the file is syntactically valid and the AST rules match
class DB
{
    public static function raw(string $sql): void {}
    public static function query(string $sql): void {}
}

class UserModel
{
    public function fill(array $data): void {}
    public static function create(array $data): void {}
}

// === XSS Vulnerability ===
if (isset($_GET['name'])) {
    $name = $_GET['name'];
    // Vulnerable: unsanitized output
    echo '<h2>Hello, ' . $name . '!</h2>';
    print('Welcome back: ' . htmlspecialchars_decode($name)); // still unsafe
}

// === SQL Injection Vulnerability ===
if (isset($_GET['id'])) {
    $id = $_GET['id'];
    // Vulnerable: raw SQL with concatenation
    DB::raw("SELECT * FROM users WHERE id = '" . $id . "' AND active = 1");
    $sql = "SELECT name FROM users WHERE id = " . $id;
    DB::query($sql);
}

// === Mass Assignment Vulnerability ===
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $input = $_POST;

    $user = new UserModel();
    // Vulnerable: unvalidated bulk assignment
    $user->fill($input);

    // Another instance of mass assignment
    UserModel::create($_POST);
}

// === Additional vulnerable patterns for demonstration ===
$comment = $_POST['comment'] ?? '';
// Short echo tag would also be caught by XssRule in real parsing
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>PHP Safeguard Vulnerable Demo</title>
    <style>
        body { font-family: system-ui, sans-serif; padding: 2rem; line-height: 1.6; }
        .warning { background: #fee; padding: 1rem; border-radius: 6px; border-left: 5px solid #c00; }
        pre { background: #f4f4f4; padding: 1rem; overflow-x: auto; }
    </style>
</head>
<body>
    <h1>PHP Safeguard — Vulnerable Demo App</h1>
    <div class="warning">
        <strong>⚠️ This application is deliberately insecure.</strong><br>
        It contains intentional examples of:<br>
        • Reflected XSS<br>
        • SQL Injection<br>
        • Laravel-style Mass Assignment
    </div>

    <h2>Test the scanner</h2>
    <p>From the project root run:</p>
    <pre>safeguard scan examples/vulnerable-app</pre>

    <h2>Or try the form (will trigger vulnerabilities)</h2>
    <form method="POST">
        <label>Name: <input name="name" value="Alice"></label><br><br>
        <label>Comment: <textarea name="comment">Test comment</textarea></label><br><br>
        <label>
            <input type="checkbox" name="is_admin" value="1">
            Make me admin (mass assignment demo)
        </label><br><br>
        <button type="submit">Submit (unsafe)</button>
    </form>

    <footer style="margin-top: 3rem; font-size: 0.9rem; color: #666;">
        <p>This file is part of the PHP Safeguard example suite.<br>
        After scanning, try <code>safeguard scan --fix</code> to see automatic remediation.</p>
    </footer>
</body>
</html>
