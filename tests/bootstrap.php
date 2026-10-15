<?php

declare(strict_types=1);

namespace Braesident\Blowfish\Tests\Fixture {
  // Only the frozen reference implementation uses these controlled clock values.
  function time() { return $GLOBALS['legacyTestSeconds'] ?? 1792022400; }
  function microtime($asFloat = false) {
    return time() + ($GLOBALS['legacyTestMicros'] ?? 134623) / 1000000;
  }
}

namespace {
  require dirname(__DIR__).'/vendor/autoload.php';
  require __DIR__.'/fixtures/Blowfish102.php';

  function check(bool $condition, string $message): void {
    if (!$condition) throw new \RuntimeException($message);
  }
  function rejects(callable $operation, string $message): void {
    try { $operation(); } catch (\UnexpectedValueException | \InvalidArgumentException $error) { return; }
    throw new \RuntimeException($message);
  }
}
