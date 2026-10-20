<?php
declare(strict_types=1);
require __DIR__.'/run.php';
$command='python3 '.escapeshellarg(__DIR__.'/http_integration.py').' '.escapeshellarg(PHP_BINARY);
passthru($command,$status);exit($status);
