<?php
require 'config.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header("Location: login.html");
    exit;
}

if (!checkRateLimit()) {
    header("Location: login.html?error=rate_limit");
    exit;
}

if (!verifyCsrfToken($_POST['csrf_token'] ?? '')) {
    header("Location: login.html?error=csrf_failed");
    exit;
}

$email = trim($_POST['email']);
$password = $_POST['password'];

try {
    $stmt = $pdo->prepare("SELECT id, username, password FROM users WHERE email = ?");
    $stmt->execute([$email]);
    $user = $stmt->fetch();
    
    if ($user && password_verify($password, $user['password'])) {
        $_SESSION['user_id'] = $user['id'];
        $_SESSION['username'] = $user['username'];
        session_regenerate_id(true);
        header("Location: dashboard.php");
        exit;
    }
    
    $_SESSION['login_attempts'] = ($_SESSION['login_attempts'] ?? 0) + 1;
    header("Location: login.html?error=invalid_credentials");
} catch (PDOException $e) {
    error_log($e->getMessage());
    header("Location: login.html?error=database_error");
}
