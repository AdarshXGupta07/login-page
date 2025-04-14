<?php
// Strict error reporting for development
error_reporting(E_ALL);
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);

// Start secure session
session_start([
    'cookie_lifetime' => 86400,
    'cookie_secure'   => true,
    'cookie_httponly' => true,
    'use_strict_mode' => true
]);

// ========================
// SECURITY HEADERS
// ========================
header("X-Frame-Options: DENY");
header("X-XSS-Protection: 1; mode=block");
header("X-Content-Type-Options: nosniff");
header("Referrer-Policy: strict-origin-when-cross-origin");
header("Content-Security-Policy: default-src 'self'");

// ========================
// DATABASE CONFIGURATION
// ========================
define('DB_HOST', 'localhost');
define('DB_NAME', 'auth_system');
define('DB_USER', 'root');
define('DB_PASS', '');
define('DB_CHARSET', 'utf8mb4');

// ========================
// CSRF PROTECTION
// ========================
function generateCsrfToken(): string {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function validateCsrfToken(string $token): bool {
    return isset($_SESSION['csrf_token']) && 
           hash_equals($_SESSION['csrf_token'], $token);
}

// ========================
// PASSWORD HASHING
// ========================
function hashPassword(string $password): string {
    return password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);
}

function verifyPassword(string $password, string $hash): bool {
    return password_verify($password, $hash);
}

// ========================
// DATABASE CONNECTION
// ========================
try {
    $dsn = "mysql:host=" . DB_HOST . ";dbname=" . DB_NAME . ";charset=" . DB_CHARSET;
    $options = [
        PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES   => false,
        PDO::ATTR_PERSISTENT         => false
    ];

    $pdo = new PDO($dsn, DB_USER, DB_PASS, $options);
    
    // Test connection (remove in production)
    $pdo->query("SELECT 1")->fetch();

} catch (PDOException $e) {
    error_log('Database error: ' . $e->getMessage());
    die('System temporarily unavailable. Please try again later.');
}

// ========================
// RATE LIMITING
// ========================
function checkRateLimit(string $action, int $maxAttempts = 5, int $timeout = 300): bool {
    $key = 'rate_limit_' . $action;
    
    if (!isset($_SESSION[$key])) {
        $_SESSION[$key] = [
            'attempts' => 0,
            'last_attempt' => time()
        ];
    }

    if ($_SESSION[$key]['attempts'] >= $maxAttempts) {
        if (time() - $_SESSION[$key]['last_attempt'] < $timeout) {
            return false;
        }
        // Reset after timeout
        unset($_SESSION[$key]);
    }
    
    return true;
}

// ========================
// INPUT SANITIZATION
// ========================
function sanitizeInput($data) {
    if (is_array($data)) {
        return array_map('sanitizeInput', $data);
    }
    return htmlspecialchars(trim($data), ENT_QUOTES, 'UTF-8');
}

// Initialize CSRF token if not exists
if (empty($_SESSION['csrf_token'])) {
    generateCsrfToken();
}
?>
