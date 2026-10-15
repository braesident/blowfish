# braesident/blowfish

PHP-Bibliothek zum Verschlüsseln und Entschlüsseln von Zeichenfolgen mit Blowfish.
Neue Werte verwenden ein versioniertes, authentifiziertes Speicherformat; Werte
aus Version 1.0.2 bleiben über einen separaten Legacy-Leser lesbar.
Die öffentliche Klasse ist `Braesident\Blowfish\Blowfish`.

## Installation und Verwendung

Benötigt werden PHP ab 7.1.2, `ext-hash` und `phpseclib/phpseclib` 3.x. Composer
installiert die Abhängigkeiten; ein einzelnes Einbinden von `src/Blowfish.php`
ohne Composer-Autoloader reicht für neue Verschlüsselungen nicht mehr aus.

Als Abhängigkeit einer Anwendung über Composer installieren:

```sh
composer require braesident/blowfish
```

Für die Entwicklung im geklonten Bibliotheks-Repository:

```sh
composer install
composer test
```

```php
require __DIR__.'/vendor/autoload.php';

use Braesident\Blowfish\Blowfish;

// Hier den unveränderten, sicher verwahrten Anwendungsschlüssel verwenden.
$cipher = new Blowfish($existingKey);
$encrypted = $cipher->Encrypt('Zugangsdaten mit Umlauten äöü');
$plain = $cipher->Decrypt($encrypted);

// Einen neuen Schlüssel einmalig erzeugen und sicher verwahren.
// Bereits verwendete Schlüssel nicht ohne eine gesonderte Datenmigration ersetzen.
$newKey = Blowfish::GenerateKey();
```

`GenerateKey()` erzeugt standardmäßig 32 alphanumerische Zeichen über `random_int`.
Eine andere Länge muss als positive Ganzzahl übergeben werden. Neue
Verschlüsselungen benötigen einen nicht leeren Schlüssel. Eine bereits vorhandene
Schlüsseldatei oder Konfiguration wird von dieser Bibliothek niemals geändert.

## Fehler und Reparatur

Version 1.0.2 verwendet Gleitkommazahlen in der Schlüsselaufbereitung und in den
Blockoperationen. Ohne durchgängige Begrenzung auf 32 Bit wachsen Zwischenwerte
so stark, dass ganzzahlige Bits verloren gehen. Deshalb können bestimmte
Schlüssel abhängig vom Inhalt und vom zeitbasierten Initialisierungsvektor Werte
erzeugen, die sich anschließend nicht korrekt entschlüsseln lassen.

Eine nachträgliche Änderung dieser Rechenoperationen würde auch den Schlüsselplan
für bestehende Daten verändern. Die Reparatur trennt deshalb zwei Verfahren:

- **Alte Werte lesen:** `Internal/LegacyBlowfish.php` bewahrt die historischen
  Konstanten, die Schlüsselaufbereitung und die Blockoperationen. Dieser Leser
  darf keine neuen Werte verschlüsseln. Seine Ergebnisse einschließlich der alten
  Leerzeichenauffüllung und HTML-Dekodierung bleiben erhalten.
- **Neue Werte schreiben und lesen:** phpseclib übernimmt die Blowfish-CBC-
  Blockverschlüsselung. Jeder Wert erhält zufälliges Salt und IV, separate
  abgeleitete Schlüssel und einen HMAC über den vollständigen Umschlag. Neue Werte
  bewahren die Klartextbytes exakt, einschließlich Unicode, Nullbytes und
  führenden bzw. abschließenden Leerzeichen.

Der an die Bibliothek übergebene Schlüssel bleibt unverändert. Es gibt keine
automatische Migration oder Neuverschlüsselung bestehender Werte.
Schon vor dem Update korrekt lesbare CBC-Werte bleiben lesbar. Bereits mit der
alten Implementierung beschädigte Werte lassen sich ohne verlässlichen
ursprünglichen Klartext nicht allgemein wiederherstellen; der Leser rät keine
Ersatzwerte und verändert diese Datensätze nicht.

## Speicherformat v2

Das Ergebnis bleibt eine Base64-Zeichenfolge. Nach dem Dekodieren hat ein neuer
Wert folgenden Aufbau:

| Offset | Länge | Inhalt |
| --- | --- | --- |
| 0 | 8 | Magic, hexadezimal `89 42 42 46 0d 0a 1a 0a` |
| 8 | 1 | Formatversion `02` |
| 9 | 16 | zufälliges Salt |
| 25 | 8 | zufälliger CBC-Initialisierungsvektor |
| 33 | Vielfaches von 8, mindestens 8 | Blowfish-CBC mit PKCS#7-Padding |
| danach | 32 | HMAC-SHA-256 über alle vorangehenden Bytes |

HKDF-SHA-256 erzeugt aus dem unveränderten Anwendungsschlüssel und dem Salt
64 Bytes mit dem Kontext `braesident/blowfish/storage/v2`: Die ersten 32 Bytes
sind der Verschlüsselungsschlüssel, die weiteren 32 Bytes der HMAC-Schlüssel.
Der HMAC wird mit `hash_equals` vor der Entschlüsselung geprüft. Salt und IV
stammen aus `random_bytes`. Die PHP-Engine von phpseclib vermeidet eine Abhängigkeit
von der Blowfish-Verfügbarkeit in OpenSSL.

Ein erkanntes v2-Format fällt bei falschem Schlüssel, unbekannter Version,
fehlgeschlagener Authentifizierung oder ungültiger Länge **nicht** auf den alten
Leser zurück, sondern wirft eine `UnexpectedValueException`. Ein leerer Schlüssel
für v2 führt zu einer `InvalidArgumentException`. Leere oder nicht als Base64
dekodierbare Eingaben liefern wie bisher einen leeren String. Historische Daten
besitzen keinen Authentifizierungscode; bei ihnen kann ein falscher Schlüssel
nicht zuverlässig erkannt werden.

Neue Datensätze sind vor Base64 `65 + 8 × (floor(Klartextlänge / 8) + 1)` Bytes
lang. Die verwendete Ablage muss den längeren Base64-Wert vollständig speichern
können. Bei Datenbankspalten sind deren Größenlimits zu prüfen; je nach
Datenbanksystem eignen sich beispielsweise `TEXT`, `LONGTEXT` oder `NVARCHAR(MAX)`.

## Update und Rückwärtskompatibilität

1. Verschlüsselte Daten und den zugehörigen Anwendungsschlüssel gemeinsam sichern.
2. Das neue Paket einschließlich Composer-Abhängigkeiten auf allen Instanzen
   ausrollen, die auf dieselben Daten zugreifen. Lang laufende Worker neu starten.
3. Bestehende Werte mit unverändertem Schlüssel lesen; neue Werte werden ab dem
   ersten Schreibzugriff im v2-Format angelegt. Ein reiner Lesezugriff schreibt
   nichts zurück.

**Die Leserkompatibilität ist einseitig:** Die reparierte Bibliothek liest alte und
neue Werte. Version 1.0.2 kann neue v2-Werte nicht lesen. Ein Rücksetzen ausschließlich
des Pakets auf 1.0.2 ist nach neuen Schreibzugriffen daher kein geeigneter Rollback.
Für einen Rollback muss der neue Leser erhalten bleiben oder ein zusammengehöriger
Stand von Anwendung, gespeicherten Daten und Schlüssel wiederhergestellt werden.

Die Prüfung der Altwerte wurde auf PHP 8.3, 64 Bit durchgeführt. Die historischen
Rechenoperationen sind absichtlich eingefroren; eine Übertragung alter Daten von
einer anderen PHP-/Integer-Umgebung muss separat geprüft werden.

Anwendungstests, die bestimmte Schlüssel wegen des Fehlers in Version 1.0.2
ausdrücklich als unbrauchbar erwarten, müssen beim Paketupdate angepasst werden.
Diese Schlüssel sind mit dem neuen Verfahren für neue Verschlüsselungen
verwendbar. Bestehende Schlüsselprüfungen können weiterhin Roundtrips testen.

## Tests

`composer test` benötigt keine Datenbank und keine Anwendungsschlüssel. Die
Suite deckt ab:

- veröffentlichte Blowfish-Testvektoren;
- 48 feste, ausschließlich künstliche Datensätze aus Version 1.0.2, darunter
  46 lesbare Werte und zwei schon vorher beschädigte Ergebnisse;
- eine deterministische Reproduktion desselben Fehlerschlüssels mit einem
  funktionierenden und einem fehlerauslösenden Zeitstempel;
- exakte Roundtrips für Unicode, binäre Daten, Leerzeichen, leeren Text,
  Blockgrenzen und längere Inhalte;
- falsche Schlüssel, Änderungen an jedem Byte eines v2-Werts, abgeschnittene und
  verlängerte Umschläge;
- gemischtes Lesen alter und neuer Werte mit derselben Instanz;
- zufällige Schlüssel mit Vergleich gegen den eingefrorenen 1.0.2-Leser.

Standardmäßig werden 256 zufällige Schlüssel mit je 16 Werten geprüft. Für einen
größeren Lauf unter PowerShell:

```powershell
$env:BLOWFISH_TEST_KEYS = '2000'
$env:BLOWFISH_TEST_VALUES = '32'
composer test
```

`tests/fixtures/Blowfish102.php` enthält den alten Quelltext aus Commit
`5850fce56d2ffc4f145f06a7f923395046dabcf0`, lediglich unter einem Test-Namespace.
`tests/bootstrap.php` steuert ausschließlich dessen Uhrzeit. Die gespeicherten
Fixtures in `tests/fixtures/legacy-1.0.2.json` dürfen nicht mit dem neuen Verfahren
neu erzeugt werden. Vergleiche mit dem alten Leser verlangen exakt dieselben
Bytes; sie behaupten nicht, bereits beschädigte Daten wiederherzustellen.

Referenzen: [Blowfish-Testvektoren](https://www.schneier.com/wp-content/uploads/2015/12/vectors-2.txt),
[phpseclib](https://phpseclib.com/docs/symmetric),
[PHP HKDF](https://www.php.net/manual/en/function.hash-hkdf.php).
