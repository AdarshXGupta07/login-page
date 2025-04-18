<?php
require 'config.php';

// Validate CSRF token
if ($_SERVER['REQUEST_METHOD'] === 'POST' && verifyCsrfToken($_POST['csrf_token'] ?? '')) {
    // Unset all session variables
    $_SESSION = array();

    // Delete session cookie
    if (ini_get("session.use_cookies")) {
        $params = session_get_cookie_params();
        setcookie(
            session_name(),
            '',
            time() - 42000,
            $params["path"],
            $params["domain"],
            $params["secure"],
            $params["httponly"]
        );
    }

    // Destroy session
    session_destroy();

    // Redirect to login with success message
    header("Location: login.html?logout=success");
    exit;
} else {
    // Invalid CSRF token or direct access
    header("Location: dashboard.php");
    exit;
}
?>
