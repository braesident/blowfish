<?php

declare(strict_types=1);

namespace Braesident\Blowfish;

use Braesident\Blowfish\Internal\LegacyBlowfish;
use InvalidArgumentException;
use phpseclib3\Crypt\Blowfish as StandardBlowfish;
use UnexpectedValueException;

// Retain the historical constant for consumers that reference it. New writes
// always use CBC; the legacy decoder must not depend on a global mode switch.
if (!\defined('CBC')) {
  \define('CBC', 1);
}

require_once __DIR__.'/Internal/LegacyBlowfish.php';

/**
 * Versioned Blowfish storage with a read-only decoder for pre-v2 ciphertexts.
 * The caller's key stays unchanged; format-specific keys are derived in memory.
 */
final class Blowfish
{
  private const MAGIC = "\x89BBF\r\n\x1a\n";
  private const VERSION = "\x02";
  private const SALT_BYTES = 16;
  private const IV_BYTES = 8;
  private const MAC_BYTES = 32;
  private const HEADER_BYTES = 9;

  private $key;
  private $legacy;

  public function __construct($key)
  {
    $this->key = (string) ($key ?? '');
  }

  /** Encrypt exact bytes; no HTML conversion or ambiguous space padding. */
  public function Encrypt($text)
  {
    $salt = random_bytes(self::SALT_BYTES);
    $iv = random_bytes(self::IV_BYTES);
    [$encryptionKey, $authenticationKey] = $this->keys($salt);
    $cipher = $this->cipher($encryptionKey, $iv);
    $payload = self::MAGIC.self::VERSION.$salt.$iv.$cipher->encrypt((string) $text);

    return base64_encode($payload.hash_hmac('sha256', $payload, $authenticationKey, true));
  }

  /**
   * Detect the storage format. Recognized v2 data never falls back to legacy
   * decoding after a failed authentication, unsupported version or bad length.
   */
  public function Decrypt($text)
  {
    $text = (string) $text;
    $decoded = base64_decode($text, true);
    if (false === $decoded || '' === $decoded) {
      return '';
    }

    if (strncmp($decoded, self::MAGIC, strlen(self::MAGIC)) === 0) {
      return $this->decryptVersioned($decoded);
    }

    // Real legacy records contain one 8-byte IV and complete 8-byte blocks.
    // A v2 record has length 1 mod 8, so damaged magic cannot silently select
    // the legacy reader merely because its first bytes were changed.
    if (strlen($decoded) < 8 || strlen($decoded) % 8 !== 0) {
      throw new UnexpectedValueException('Invalid Blowfish ciphertext format.');
    }
    if (null === $this->legacy) {
      $this->legacy = new LegacyBlowfish($this->key);
    }

    return $this->legacy->Decrypt($text);
  }

  /** Generate alphanumeric keys using the operating system's secure RNG. */
  public static function GenerateKey($length = 32)
  {
    if (!is_int($length) || $length < 1) {
      throw new InvalidArgumentException('Key length must be a positive integer.');
    }
    $alphabet = 'abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    $key = '';
    for ($index = 0; $index < $length; ++$index) {
      $key .= $alphabet[random_int(0, strlen($alphabet) - 1)];
    }

    return $key;
  }

  private function decryptVersioned(string $decoded): string
  {
    $overhead = self::HEADER_BYTES + self::SALT_BYTES + self::IV_BYTES + self::MAC_BYTES;
    if (strlen($decoded) < $overhead + 8 || (strlen($decoded) - $overhead) % 8 !== 0) {
      throw new UnexpectedValueException('Invalid Blowfish ciphertext length.');
    }
    if ($decoded[strlen(self::MAGIC)] !== self::VERSION) {
      throw new UnexpectedValueException('Unsupported Blowfish ciphertext version.');
    }

    $salt = substr($decoded, self::HEADER_BYTES, self::SALT_BYTES);
    [$encryptionKey, $authenticationKey] = $this->keys($salt);
    $payload = substr($decoded, 0, -self::MAC_BYTES);
    $providedMac = substr($decoded, -self::MAC_BYTES);
    $expectedMac = hash_hmac('sha256', $payload, $authenticationKey, true);
    if (!hash_equals($expectedMac, $providedMac)) {
      throw new UnexpectedValueException('Blowfish ciphertext authentication failed.');
    }

    $ivOffset = self::HEADER_BYTES + self::SALT_BYTES;
    $iv = substr($decoded, $ivOffset, self::IV_BYTES);
    $encrypted = substr($payload, $ivOffset + self::IV_BYTES);

    return $this->cipher($encryptionKey, $iv)->decrypt($encrypted);
  }

  /** Derive separate encryption and MAC keys for every stored value. */
  private function keys(string $salt): array
  {
    if ('' === $this->key) {
      throw new InvalidArgumentException('New Blowfish ciphertexts require a non-empty key.');
    }
    $material = hash_hkdf('sha256', $this->key, 64, 'braesident/blowfish/storage/v2', $salt);

    return [substr($material, 0, 32), substr($material, 32, 32)];
  }

  private function cipher(string $key, string $iv): StandardBlowfish
  {
    $cipher = new StandardBlowfish('cbc');
    // Use phpseclib's portable integer implementation; OpenSSL 3 may not offer BF.
    $cipher->setPreferredEngine('PHP');
    $cipher->setKey($key);
    $cipher->setIV($iv);

    return $cipher;
  }
}
