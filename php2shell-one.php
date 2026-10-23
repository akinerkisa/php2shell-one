<?php

/*
 * PHP2Shell One - read-only PHP runtime inventory.
 *
 * Usage:
 *   php php2shell-one.php
 *   php php2shell-one.php --json
 */

if (PHP_SAPI !== 'cli') {
    http_response_code(403);
    header('Content-Type: text/plain; charset=utf-8');
    header('Cache-Control: no-store');
    header('X-Robots-Tag: noindex, nofollow');
    echo "PHP2Shell One is CLI-only.\n";
    exit(1);
}

function one_ini_value($name)
{
    $value = ini_get($name);
    return $value === false ? null : $value;
}

function one_bool_value($value)
{
    if ($value === null) {
        return null;
    }

    return filter_var($value, FILTER_VALIDATE_BOOLEAN);
}

function one_display($value)
{
    if ($value === null) {
        return 'unknown';
    }
    if (is_bool($value)) {
        return $value ? 'on' : 'off';
    }
    if ($value === '') {
        return '(empty)';
    }
    return (string) $value;
}

$args = array_slice($argv, 1);
if (in_array('--help', $args, true) || in_array('-h', $args, true)) {
    echo "Usage: php php2shell-one.php [--json]\n";
    echo "Print a read-only inventory of the current PHP CLI runtime.\n";
    exit(0);
}

$allowed = array('--json');
foreach ($args as $arg) {
    if (!in_array($arg, $allowed, true)) {
        fwrite(STDERR, "Unknown option: " . $arg . "\n");
        exit(1);
    }
}

$uploadProgress = one_ini_value('session.upload_progress.enabled');
$fileUploads = one_ini_value('file_uploads');

$report = array(
    'tool' => 'PHP2Shell One',
    'schema_version' => 1,
    'collected_at_utc' => gmdate('c'),
    'runtime' => array(
        'php_version' => PHP_VERSION,
        'php_version_id' => PHP_VERSION_ID,
        'sapi' => PHP_SAPI,
        'os_family' => defined('PHP_OS_FAMILY') ? PHP_OS_FAMILY : PHP_OS,
        'loaded_ini' => php_ini_loaded_file() ?: null,
        'scanned_ini_files' => php_ini_scanned_files() ?: null,
        'session_extension_loaded' => extension_loaded('session'),
    ),
    'configuration' => array(
        'file_uploads' => one_bool_value($fileUploads),
        'upload_max_filesize' => one_ini_value('upload_max_filesize'),
        'post_max_size' => one_ini_value('post_max_size'),
        'memory_limit' => one_ini_value('memory_limit'),
        'session.upload_progress.enabled' => one_bool_value($uploadProgress),
        'session.upload_progress.cleanup' => one_bool_value(one_ini_value('session.upload_progress.cleanup')),
        'session.upload_progress.name' => one_ini_value('session.upload_progress.name'),
        'session.upload_progress.prefix' => one_ini_value('session.upload_progress.prefix'),
    ),
    'limits' => array(
        'scope' => 'current PHP CLI runtime only',
        'patch_status' => 'not determined',
        'note' => 'Configuration inventory is not proof of vulnerability, exploitation, or patch status.',
    ),
);

if (in_array('--json', $args, true)) {
    echo json_encode($report, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL;
    exit(0);
}

echo "PHP2Shell One | PHP runtime inventory\n";
echo "PHP: " . $report['runtime']['php_version'] . " (" . $report['runtime']['sapi'] . ")\n";
echo "OS: " . $report['runtime']['os_family'] . "\n";
echo "Loaded php.ini: " . one_display($report['runtime']['loaded_ini']) . "\n";
echo "Session extension: " . one_display($report['runtime']['session_extension_loaded']) . "\n";

foreach ($report['configuration'] as $name => $value) {
    echo $name . ': ' . one_display($value) . "\n";
}

echo "\nResult: inventory only; patch status not determined.\n";
exit(0);

