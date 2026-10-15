<?php

declare(strict_types=1);

use Braesident\Blowfish\Blowfish;
use Braesident\Blowfish\Tests\Fixture\Blowfish102;
use phpseclib3\Crypt\Blowfish as StandardBlowfish;

require __DIR__.'/bootstrap.php';

// Published Blowfish vectors, independent of this package's storage envelope:
// https://www.schneier.com/wp-content/uploads/2015/12/vectors-2.txt
foreach ([
  ['0000000000000000', '0000000000000000', '4EF997456198DD78'],
  ['FFFFFFFFFFFFFFFF', 'FFFFFFFFFFFFFFFF', '51866FD5B85ECB8A'],
  ['3000000000000000', '1000000000000001', '7D856F9A613063F2'],
  ['1111111111111111', '1111111111111111', '2466DD878B963C9D']
] as [$key, $plain, $encrypted]) {
  $cipher = new StandardBlowfish('ecb');
  $cipher->setPreferredEngine('PHP');
  $cipher->disablePadding();
  $cipher->setKey(hex2bin($key));
  check(bin2hex($cipher->encrypt(hex2bin($plain))) === strtolower($encrypted), 'Published encryption vector failed');
  check(bin2hex($cipher->decrypt(hex2bin($encrypted))) === strtolower($plain), 'Published decryption vector failed');
}
echo "Published Blowfish vectors: passed\n";

$fixtures = json_decode(file_get_contents(__DIR__.'/fixtures/legacy-1.0.2.json'), true);
check(json_last_error() === JSON_ERROR_NONE && isset($fixtures['records']), 'Invalid legacy fixture file');
$readable = 0; $alreadyBroken = 0;
foreach ($fixtures['records'] as $record) {
  $cipher = new Blowfish($record['key']);
  $expected = base64_decode($record['legacyPlaintextBase64'], true);
  check($cipher->Decrypt($record['ciphertext']) === $expected, 'Frozen legacy result changed: '.$record['id']);
  $plain = base64_decode($record['plaintextBase64'], true);
  if ($record['readable']) {
    check(rtrim($expected, ' ') === rtrim($plain, ' '), 'Readable legacy fixture lost its original text');
    ++$readable;
  } else { ++$alreadyBroken; }
  // New writes must not switch the reader away from legacy or retain another salt.
  $new = $cipher->Encrypt('New value next to the old record');
  check($cipher->Decrypt($new) === 'New value next to the old record', 'Mixed-format new read failed');
  check($cipher->Decrypt($record['ciphertext']) === $expected, 'Mixed-format legacy read failed');
}
check($readable > 0 && $alreadyBroken > 0, 'Fixtures must cover both readable and already corrupt historical values');
echo "Frozen 1.0.2 records: $readable readable preserved, $alreadyBroken previously broken outputs unchanged\n";

// Same key and text, only the historical encryption timestamp differs.
$badKey = 'GSIhNgskPXxTMCg3vrpXiWoTCSnf1CRh';
$old = new Blowfish102($badKey);
$plain = 'diagnostic-only-shipping-password-0123456789';
$GLOBALS['legacyTestSeconds'] = 1792022400;
$GLOBALS['legacyTestMicros'] = 0;
check(trim($old->Decrypt($old->Encrypt($plain))) === $plain, 'Expected working historical clock case');
$GLOBALS['legacyTestMicros'] = 134623;
check(trim($old->Decrypt($old->Encrypt($plain))) !== $plain, 'Original bug no longer reproduced by frozen reference');
$new = new Blowfish($badKey);
foreach ([0, 134623, 999999] as $micros) {
  $GLOBALS['legacyTestMicros'] = $micros;
  for ($i = 0; $i < 64; ++$i) {
    check((new Blowfish($badKey))->Decrypt($new->Encrypt($plain)) === $plain, 'Bad key failed with new format');
  }
}
echo "Known broken key and time-dependent regression: passed\n";

// New format stores exact bytes, not HTML-encoded, space-padded approximations.
$edgeCases = ['', '0', '12345678', ' leading', 'trailing  ', "\0\xff\x80\0", "\r\n\t ",
  'ÄÖÜ äöü ß Straße & <Kontakt> "CRM" \' Apostroph', '日本語 😀', str_repeat('long-', 10000)];
for ($length = 1; $length <= 129; ++$length) $edgeCases[] = substr(str_repeat('block-boundary-', 10), 0, $length);
foreach (['short', str_repeat('k', 56), str_repeat('k', 128), "binary\0key\xff", 'Schlüssel-äöü'] as $key) {
  $cipher = new Blowfish($key);
  foreach ($edgeCases as $plain) {
    $encrypted = $cipher->Encrypt($plain);
    check(base64_decode($encrypted, true) !== false, 'Storage must remain strict Base64');
    check((new Blowfish($key))->Decrypt($encrypted) === $plain, 'Exact byte roundtrip failed');
  }
}
check((new Blowfish(''))->Decrypt('') === '', 'Empty legacy input contract changed');
rejects(static function () { (new Blowfish(''))->Encrypt('value'); }, 'Empty keys must not create new data');
echo "Text, binary, whitespace and block boundaries: passed\n";

$key = 'authentication-test-key';
$cipher = new Blowfish($key);
$encoded = $cipher->Encrypt('A stored API password');
$raw = base64_decode($encoded, true);
check($encoded !== $cipher->Encrypt('A stored API password'), 'Salt and IV must change between writes');
// Verify the format contract separately using the documented layout.
check(substr($raw, 0, 9) === "\x89BBF\r\n\x1a\n\x02", 'Unexpected format marker');
$material = hash_hkdf('sha256', $key, 64, 'braesident/blowfish/storage/v2', substr($raw, 9, 16));
check(hash_equals(substr($raw, -32), hash_hmac('sha256', substr($raw, 0, -32), substr($material, 32), true)), 'MAC must cover header, salt, IV and ciphertext');
$independent = new StandardBlowfish('cbc');
$independent->setKey(substr($material, 0, 32));
$independent->setIV(substr($raw, 25, 8));
check($independent->decrypt(substr($raw, 33, -32)) === 'A stored API password', 'Independent envelope decode failed');
foreach (range(0, strlen($raw) - 1) as $offset) {
  $changed = $raw;
  $changed[$offset] = chr(ord($changed[$offset]) ^ 1);
  rejects(static function () use ($cipher, $changed) { $cipher->Decrypt(base64_encode($changed)); }, 'Tampered byte accepted at '.$offset);
}
foreach (range(1, strlen($raw) - 1) as $length) {
  $truncated = substr($raw, 0, $length);
  // Short fragments cannot all be distinguished from the unauthenticated legacy IV.
  if ($length < 8) continue;
  rejects(static function () use ($cipher, $truncated) { $cipher->Decrypt(base64_encode($truncated)); }, 'Truncated versioned ciphertext accepted');
}
rejects(static function () use ($encoded) { (new Blowfish('wrong key'))->Decrypt($encoded); }, 'Wrong key must not return fake plaintext');
rejects(static function () use ($cipher, $raw) { $cipher->Decrypt(base64_encode($raw.'x')); }, 'Appended data must be rejected');
echo "Authentication, wrong key, damaged header and truncation: passed\n";

$keys = [];
for ($i = 0; $i < 128; ++$i) {
  $key = Blowfish::GenerateKey();
  check((bool) preg_match('/\A[a-zA-Z0-9]{32}\z/', $key), 'Generated key format changed');
  check(!isset($keys[$key]), 'Duplicate generated key');
  $keys[$key] = true;
}
rejects(static function () { Blowfish::GenerateKey(0); }, 'Zero-length key accepted');
echo "Secure key generation: passed\n";

// Randomized compatibility checks compare outputs byte-for-byte, including
// historical padding and existing corruption, without inventing a recovery rule.
$keysToTest = (int) (getenv('BLOWFISH_TEST_KEYS') ?: 256);
$perKey = (int) (getenv('BLOWFISH_TEST_VALUES') ?: 16);
check($keysToTest > 0 && $perKey > 0, 'Positive test counts required');
$roundtrips = 0; $oldDifferences = 0;
for ($i = 0; $i < $keysToTest; ++$i) {
  $key = Blowfish::GenerateKey();
  $new = new Blowfish($key); $old = new Blowfish102($key);
  for ($j = 0; $j < $perKey; ++$j) {
    $GLOBALS['legacyTestSeconds'] = 1609459200 + (($i + $j) % 4000) * 86400;
    $GLOBALS['legacyTestMicros'] = ($j * 7919) % 1000000;
    $plain = substr(str_repeat(hash('sha256', 'probe-'.$j), 3), 0, 1 + ($j * 17) % 192);
    $legacy = $old->Encrypt($plain);
    $previous = $old->Decrypt($legacy);
    check($new->Decrypt($legacy) === $previous, 'Old ciphertext output changed');
    $oldDifferences += (int) (trim($previous) !== $plain);
    check((new Blowfish($key))->Decrypt($new->Encrypt($plain)) === $plain, 'Randomized new ciphertext roundtrip failed');
    ++$roundtrips;
  }
  if (($i + 1) % 250 === 0) echo 'Validated '.($i + 1)." keys\n";
}
echo "$roundtrips new roundtrips and $roundtrips legacy comparisons passed; $oldDifferences original defects observed\n";
echo "All tests passed. No installation keys or database records were used.\n";
